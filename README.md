```
      .---.        .-----------
     /     \  __  /    ------
    / /     \(  )/    -----
   //////   ' \/ `   ---
  //// / // :    : ---
 // /   /  /`    '--
//          //..\\
       ====UU====UU====
           '//||\\`
             ''``

 __   __  _______  _______  _______  ___   _______
|  |_|  ||   _   ||       ||       ||   | |       |
|       ||  |_|  ||    ___||    _  ||   | |    ___|
|       ||       ||   | __ |   |_| ||   | |   |___
|       ||       ||   ||  ||    ___||   | |    ___|
| ||_|| ||   _   ||   |_| ||   |    |   | |   |___
|_|   |_||__| |__||_______||___|    |___| |_______|
```

**magpie collects what a domain leaves out in the open.**

magpie is a passive, read-only reconnaissance tool that maps and validates the `/.well-known/` directory of a domain — the small set of standardized paths (`security.txt`, `openid-configuration`, `mta-sts.txt`, `assetlinks.json`, and dozens more) that quietly describe how a domain runs its authentication, mail security, mobile apps, and vulnerability disclosure process.

```
$ magpie example.org

magpie — example.org
scanned 2026-07-20 09:14:02 UTC

WELL-KNOWN PATHS
  /.well-known/security.txt                present   text/plain
  /.well-known/openid-configuration        present   application/json
  /.well-known/mta-sts.txt                 absent    text/html
  ...

FINDINGS (3)
  DISCLOSURE
    [HIGH]   SECTXT-004 certain  security.txt's Expires date is in the past.
    [MEDIUM] CORR-013   inferred Published encryption key is unreachable or invalid.
  AUTH
    [MEDIUM] CORR-017   inferred openid-configuration advertises request_uri support without requiring pre-registration.

INFERENCE
  identity provider: Okta (https://example.okta.com)
  mail security: mode=enforce dns_activated=true
```

*(a terminal recording / screenshot belongs here — `docs/demo.gif`)*

## Install

magpie isn't published anywhere yet — get the source and build it locally:

```sh
git clone <this-repo-url>
cd magpie
make build      # -> bin/magpie
```

Requires Go (see `go.mod` for the minimum version). `make build` installs
nothing outside the repo; `./bin/magpie` is a self-contained binary you can
move wherever you like.

## Usage

**Single domain**
```sh
magpie example.org
```

**Batch mode** — scan a list of domains, one summary CSV row per domain
```sh
magpie -f domains.txt --csv > results.csv
```

**Diff mode** — only print what changed since the last saved snapshot, and fail CI on new medium+ findings
```sh
magpie example.org --save --diff --exit-code
```

**JSON mode** — full structured output, versioned schema, pipeable to `jq`
```sh
magpie example.org --json | jq '.findings[] | select(.severity == "high")'
```

Other useful flags: `--md` (paste-ready markdown report), `--sarif` (GitHub code scanning), `--compare` (context against a reference corpus), `--watch --interval 6h --webhook <url>` (continuous monitoring), `--fix` (print a corrected `security.txt`), `--ct` (expand to subdomains via certificate transparency logs), `--rules <file>` (load community correlation rules). Run `magpie --help` for the full flag reference, or `magpie explain --all` for a longform writeup of every finding ID magpie can produce.

## What magpie checks

- **Presence**, determined with a soft-404 control probe so hosts that return `200 OK` with a generic error page for everything don't produce false positives.
- **Validity** of the well-known documents required by their specs: `security.txt` (RFC 9116), `openid-configuration`, `mta-sts.txt` (RFC 8461), `assetlinks.json`, `apple-app-site-association`, and `change-password`. Every other documented path gets presence + content-type reporting.
- **Correlation** across documents — 25 rules (`CORR-001`…`CORR-025`) that catch things no single validator can see on its own, like federated auth exposed with no security contact, or two auth documents disagreeing about their issuer.
- **Inference** of the underlying stack: identity provider, mobile app identifiers, mail security posture, Matrix homeserver, ACME automation — all derived from already-fetched content, never guessed.

## Design Principles

**magpie is passive and read-only, and that is a hard constraint, not a preference.** Every scan issues exactly one HTTP GET per path documented in the IANA Well-Known URI Registry — nothing is guessed, brute-forced, or enumerated. This matters for three reasons:

1. **It's legally and ethically unambiguous.** A tool that only requests URLs a domain has already published, standardized locations doesn't need permission to run against a domain you don't control. Passive recon is the class of activity that stays clearly on the right side of unauthorized-access law without a lawyer in the loop.
2. **It's a good neighbor.** magpie is designed to be run against domains at scale (batch mode, CI pipelines, continuous watch) without ever looking like — or behaving like — a scanner someone needs to block or rate-limit defensively.
3. **It keeps the tool honest about what it knows.** Every finding traces back to content a domain chose to publish. magpie never tells you something is broken based on a guess; the [finding model](#finding-model) separates *how confidently* something was determined (`certain` / `likely` / `inferred`) from *how bad* it is (`info` / `low` / `medium` / `high`) for exactly this reason — magpie reads published configuration and cannot assess real-world exploitability, so it never tries to.

## What magpie deliberately does not do

- **No path guessing or brute forcing.** Every path magpie requests comes from the embedded IANA Well-Known URI Registry. There is no wordlist mode and there will not be one.
- **No directory enumeration.** magpie does not walk a site's structure looking for exposed files.
- **No exploitation.** magpie never sends anything beyond a GET, never submits credentials, and never attempts to trigger, confirm, or demonstrate a vulnerability. It reports what a domain has published; what to do about it is a human decision.
- **No scanning beyond the documented surface.** The one opt-in exception is `--ct`, which reads already-issued certificates from public certificate transparency logs (crt.sh) to discover subdomains — it performs no DNS brute forcing or probing to find them, and it's off by default.

## Finding model

Every finding — from a validator or from the correlation engine — carries an `id` (stable, never renumbered), a `severity` (`info`/`low`/`medium`/`high`), a `confidence` (`certain`/`likely`/`inferred` — describing how the finding was derived, not how worried to be), a `category` (`disclosure`/`auth`/`mail`/`mobile`/`hygiene`), a one-sentence `message`, the `evidence` that triggered it, and a `spec_ref` where applicable. There is deliberately no likelihood or exploitability score — see Design Principles above.

## Reference corpus (`--compare`)

`--compare` renders your scan alongside a small, curated sample describing what well-run domains typically publish. **This is editorial context, not a statistical population** — it was assembled by judgment, not by surveying a representative sample of the web, and its own methodology and update process are documented in `internal/compare/corpus.json`. Treat it as a sanity check, not a benchmark.

## Contributing

New validators, correlation rules, and identity-provider/registry entries are all designed to be added without touching unrelated code — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
