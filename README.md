# snyk-cli-branch-scan

Scan a branch with the Snyk CLI (SAST, IaC and open source), record the commit it was scanned at, and add a code snippet and a stable identity to every finding.

The Snyk CLI returns the file and line of each finding, but not the commit ID or the code itself. This repo adds both, so a downstream platform (a triage portal, a release gate, a ticketing system) can show per-branch results with the code, without using the Snyk UI, the Import API or any branch setting in Snyk.

An unofficial helper, not a Snyk product feature.

## How it works

```
Developer or pipeline requests a scan
        |
        v
   Jenkins job  -->  1. clean checkout of the branch (GitHub or GitHub Enterprise)
                     2. snyk code test, snyk iac test, snyk test   (outbound to your Snyk tenant)
                     3. add snippets (read from the same commit) and finding IDs
                     4. write manifest.json + enriched.json
        |
        v
   Downstream platform stores the bundle, compares scans by key, gates, raises tickets
```

1. **Clean checkout.** The step refuses to run if the workspace has any change or untracked file, because line numbers would not match the commit. It records the commit SHA and branch.
2. **Scan.** `snyk code test` (SARIF), `snyk iac test` and `snyk test` (JSON). If one scan fails, the others still run and the manifest records which failed.
3. **Add snippets.** For each finding, the flagged lines plus 3 lines of context are read from the same commit, either from the clean checkout (default) or from GitHub at that SHA. SAST findings also get each step of the source-to-sink data flow.
4. **Identity.** SAST findings keep Snyk's own finding ID. IaC and open source have none, so a stable key is built from the rule, file and resource path or code hash.
5. **Bundle.** `manifest.json` (repo, branch, commit, build, CLI version, status of each scan) and `enriched.json` (the findings).

## Usage

    SCA_PREP="npm ci --ignore-scripts" BRANCH=feature/x BUILD_ID=123 \
      ./snyk_branch_scan.sh <checkout_dir> <owner/repo> <out_dir>

See `Jenkinsfile.example`. All options are documented at the top of `snyk_branch_scan.sh`.

| Variable | Purpose |
|---|---|
| `BRANCH`, `BUILD_ID` | Branch name (a detached HEAD without it is refused) and CI build id |
| `SNYK_ORG` | Org id passed as `--org` |
| `SCA_PREP` | Command that installs dependencies. Open source scanning is skipped if unset |
| `SCA_ARGS`, `MANIFEST` | Extra `snyk test` arguments, and the manifest used for the snippet line |
| `IAC_PATHS` | Files or folders for `snyk iac test`. Needed when the repo holds JSON or YAML the IaC scanner cannot parse |
| `ENRICH` | `local` (default, reads the checkout), `github` (fetches at the commit) or `none` (raw results only) |
| `GITHUB_TOKEN`, `GITHUB_API_URL` | For `ENRICH=github`. Use `https://<host>/api/v3` for GitHub Enterprise |

Requirements: Snyk CLI 1.1307.0 or later, `SNYK_TOKEN`, Python 3 (standard library only), git. Give each scan its own output folder (for example one per commit SHA). Scans share no state, so several branches of the same repo can run at the same time.

Output per scan: `manifest.json`, `code.sarif`, `iac.json`, `sca.json`, `enriched.json`, `enriched.md`.

### Exit codes
| Exit | Meaning |
|---|---|
| 0 | All scans done |
| 2 | Guard stopped the run (dirty workspace, detached HEAD, commit not on the remote in GitHub mode) |
| 3 | Every scan failed |
| 4 | Partial: at least one scan failed, the rest is in the bundle |
| 5 | Snippet enrichment failed |

### Fields on each finding
`repo`, `branch`, `commit_id`, `build_id`, `snyk_id` (SAST only), `key`, `finding_id` (repo, branch and Snyk ID, or the key when there is none), `rule`, `title`, `severity`, `message`, `file`, `start`, `end`, `snippet`, `flow` (SAST), `resource_path` and `resolve` (IaC).

## Validation

Run on the public OWASP Juice Shop, plus small sample projects. Snyk CLI 1.1307.2.

| Test | Result |
|---|---|
| Two branches of the same repo scanned at the same time | No interference |
| Matching snippets, full repo | 510 of 510 (214 SAST, 32 IaC, 264 open source) |
| Branch with 5 lines inserted in two files | 17 findings moved line, all kept the same key and Snyk ID |
| One new vulnerable file added | Exactly 2 new keys, nothing lost |
| Monorepo, scan from a subfolder | Subfolder detected, 10 of 10 snippets matched |
| Other ecosystems (open source) | pip 100 of 100, Go 4 of 4, Maven 74 of 74 |
| Modified or untracked file after checkout | Refused by the guard |
| No route to Snyk, or an invalid token | Every scan marked `failed`, never reported as clean |
| Snippets fetched from GitHub | One request per file with findings, about 19 files per second with 8 in parallel |

## Limits

- Lines match only if the scan saw exactly the committed files. The guard catches changes made after checkout, not changes made before the commit.
- Results are not published to the Snyk UI.
- The CLI sends its analysis to your Snyk tenant, so the runner needs outbound access to it.
- Snippet lookup for open source supports `package.json`, `requirements*.txt`, `go.mod` and `pom.xml`. Other manifests need their own lookup.
- IaC findings have one line, not a range.
- A JSON or YAML file the IaC scanner cannot parse fails the whole IaC scan. Use `IAC_PATHS`.
- Not tested: GitHub Enterprise through a broker, files over 100 MB, very large repository counts.

## Tests

    python3 -m unittest discover -s tests
