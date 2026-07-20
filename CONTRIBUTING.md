# Contributing to magpie

Thanks for considering a contribution. This document covers the two most
common contributions — a new validator and a new correlation rule — plus the
smaller data files that are safe to extend without touching Go code.

Before anything else: `make build test lint` should pass. See the Makefile
for the exact commands CI runs.

## Project layout

```
cmd/magpie/           main, cobra commands
internal/scan/        fetcher, concurrency, soft404 control logic
internal/registry/    IANA registry embed and update
internal/validate/    Validator interface and per-path implementations
internal/correlate/   rules engine (rules.json + condition DSL + builtins)
internal/infer/       stack inference mappings (idp_patterns.json etc.)
internal/render/      terminal, json, markdown, csv, sarif output
internal/snapshot/    save, diff, watch
internal/finding/     finding model, severity, confidence, category
internal/fix/         corrected artifact generation
internal/explain/     longform finding documentation
internal/compare/     the --compare reference corpus
testdata/             fixture responses for every validator
```

## Adding a new validator

A validator inspects one documented well-known path's fetched content and
turns it into findings and facts. Look at `internal/validate/changepassword.go`
for the smallest complete example, or `internal/validate/securitytxt.go` for
the most thorough one.

1. **Pick the registry path.** It must already exist in
   `internal/registry/iana_wellknown.json` (add an entry there first if it
   doesn't — see "Updating the IANA registry" below).

2. **Implement the `Validator` interface** (`internal/validate/validator.go`):

   ```go
   type Validator interface {
       Path() string
       Validate(ctx Context) Output
   }
   ```

   `ctx.Result` is the fetch outcome — check `ctx.Result.Presence` first;
   most validators return immediately if it isn't `scan.PresencePresent`.
   `Output.Findings` is what gets reported; `Output.Facts` is a
   `map[string]string` of anything downstream code (the correlation engine,
   the inference layer, `--fix`) might need — see existing validators for the
   fact keys already in use before inventing new ones.

3. **Register it** in the same file's `init()`:

   ```go
   func init() { Register(MyValidator{}) }
   ```

4. **Give every finding ID a stable name and register its explanation in the
   same file**, right next to the `init()` that registers the validator:

   ```go
   explain.Register(explain.Doc{
       ID: "MYVAL-001", Severity: finding.SeverityMedium, Confidence: finding.ConfidenceCertain,
       Category: finding.CategoryHygiene,
       Message: "One sentence, plain language, no marketing tone.",
       SpecRef: "RFC XXXX §Y",
       Explanation: "What it means, why it matters, and a concrete remediation step.",
   })
   ```

   IDs are permanent once shipped: never renumber or reuse one, even if the
   check it described changes. Doc registration lives in the *same file* as
   the code that emits the finding, deliberately — see the comment atop
   `internal/explain/explain.go` for why.

5. **Write table-driven tests** in `<name>_test.go`, with fixtures for
   anything beyond a couple of lines of inline JSON/text under
   `testdata/<name>/`. Cover: the happy path, each finding your validator can
   emit, and the "not present" short-circuit. See
   `internal/validate/securitytxt_test.go` for the fullest example.

6. If your validator needs data beyond `ctx.Result` — an extra GET against a
   URL the document itself published (`ctx.Fetch`), or a DNS TXT lookup
   (`ctx.LookupTXT`) — those are already threaded through `Context`. Don't
   add new ones without a strong reason: every extra network capability is
   something `internal/orchestrate` has to wire up for every call site
   (single scan, batch, `--fix`, `--watch`), and it's easy to accidentally
   violate the one-GET-per-documented-path constraint.

## Adding a correlation rule

Correlation rules live as **data**, not Go code, in
`internal/correlate/rules.json`, specifically so they can be reviewed,
diffed, and contributed without touching the rules engine. Most rules never
need a line of Go.

### The condition format

Each rule is a JSON object:

```json
{
  "id": "CORR-030",
  "severity": "medium",
  "confidence": "inferred",
  "category": "hygiene",
  "message": "One sentence describing the finding.",
  "evidence": "optional template, e.g. {{fact:security.txt.expires_days_remaining}}",
  "spec_ref": "optional spec citation",
  "explanation": "Longform: what it means, why it matters, how to fix it. This is what `magpie explain CORR-030` prints.",
  "when": { /* condition tree, see below */ }
}
```

`when` is built from these node types (exactly one field set per node):

| Node | Shape | Matches when |
|---|---|---|
| `presence` | `{"path": "security.txt", "in": ["absent","soft404"]}` | the path's presence is one of `in` — valid values: `present`, `absent`, `soft404`, `error`, `redirected-offsite` |
| `fact` | `{"path": "security.txt", "key": "policy_present", "op": "eq", "value": "false"}` | a fact comparison. `op`: `eq`, `ne`, `contains`, `not_contains`, `not_empty`, `exists`, `not_exists`, `lt`/`lte`/`gt`/`gte` (numeric) |
| `fact_compare` | `{"a": {"path":"a","key":"issuer"}, "b": {"path":"b","key":"issuer"}, "op": "conflict"}` | compares two facts, possibly on different documents. `op`: `eq`, `ne`, `conflict` (true only when both exist, are non-empty, and differ) |
| `finding_exists` | `{"path": "security.txt", "id": "SECTXT-010"}` | that path's validator already emitted the given finding ID |
| `clean_count_min` | `{"min": 3}` | at least `min` documents across the whole scan are present with zero validator findings |
| `and` / `or` | array of condition nodes | boolean combination |
| `not` | a single condition node | negation |

`message` and `evidence` can reference `{{host}}`, `{{presence:<path>}}`, and
`{{fact:<path>.<key>}}` — see any existing rule for examples. Run
`go test ./internal/correlate/...` after adding a rule; add a test in
`internal/correlate/rules_test.go` that constructs a minimal `Snapshot`
proving your rule fires (and, ideally, one proving it doesn't fire on a
similar-but-not-matching input).

### What the condition language can't express (and how to load extra rules)

A handful of rules (`CORR-007`, `CORR-022`, `CORR-024` — search `rules.json`
for `"builtin"`) need real cross-document iteration or a live DNS lookup that
the declarative condition tree above can't express. Those are implemented as
named Go functions registered in `internal/correlate/builtins.go`; the rule's
metadata (severity, message, explanation, etc.) still lives in `rules.json`.
If you hit a case that genuinely needs this, open an issue first — most
things that look like they need a builtin turn out to be expressible with
`fact_compare` plus a fact the relevant validator can compute directly (see
how `security.txt`'s `contact_external_domain` fact avoids needing a builtin
for what could have been a cross-document domain comparison).

### Loading your own rules without a PR

`--rules <file>` loads a JSON array of rule objects in the exact shape
above. A rule whose `id` matches a built-in rule replaces it entirely
(useful for tuning severity/confidence to your organization's risk
tolerance); a new `id` is appended. Only the declarative condition language
is available this way — `"builtin"` rules can't be defined outside the
binary.

## Updating the IANA registry

`internal/registry/iana_wellknown.json` is the embedded fallback; a local
cache at `~/.magpie/registry_cache.json` (written by `magpie registry
update`) takes precedence when present. To propose a new permanent addition
to the embedded copy, add an entry with `path`, `reference`, `status`,
`content_type`, `kind` (`json`, `text`, `html`, or empty if unspecified), and
`description`, keeping the array sorted by `path`.

## Updating the identity provider patterns or reference corpus

- `internal/infer/idp_patterns.json` — substring patterns matched against an
  `openid-configuration` issuer URL, first match wins. List more specific
  patterns before broader ones.
- `internal/infer/bugbounty_patterns.json` — substring patterns matched
  against `security.txt` `Contact` URLs to identify which bug bounty
  platform (if any) a program runs on. Same first-match-wins rule.
- `internal/compare/corpus.json` — the `--compare` reference sample. Its
  `methodology` field documents how to refresh it with real measurements
  instead of editorial judgment; please update `methodology` and `updated`
  alongside any data change so the corpus never silently drifts from what it
  claims to be.

## Tests

- No test may hit the live internet — use `httptest` servers (see
  `internal/scan/fetcher_test.go`) or synthetic fixtures constructed in Go
  (see `internal/correlate/rules_test.go`).
- Keep output deterministic: fixed ordering, no wall-clock-dependent
  assertions without pinning `time.Now()` via a parameter.
- `make test` runs everything with `-race`.
