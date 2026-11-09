#!/usr/bin/env bash
# Jenkins step: scan one branch with the Snyk CLI (SAST, IaC, open source) and write a bundle for a downstream platform.
#
# Usage:  ./snyk_branch_scan.sh <checkout_dir> <owner/repo> <out_dir>
#         <checkout_dir> may be the repo root or a subfolder of it (monorepo). The subfolder is detected.
#
# Env:    BRANCH            branch name (default: $BRANCH_NAME; a detached HEAD without it is refused)
#         BUILD_ID          CI build id (default: $BUILD_ID, else "local")
#         SNYK_ORG          Snyk org id for --org (optional)
#         SCA_PREP          command that installs dependencies, e.g. "npm ci --ignore-scripts" (SCA is skipped if unset)
#         MANIFEST          manifest that declares dependencies for SCA snippets (default package.json).
#                           Snippet lookup supports package.json, requirements*.txt, go.mod and pom.xml.
#         SCA_ARGS          extra arguments for `snyk test`, e.g. "--file=requirements.txt --command=.venv/bin/python"
#         IAC_PATHS         space separated files/folders for `snyk iac test` (default: the whole checkout dir).
#                           Set it when the repo holds JSON/YAML the IaC scanner cannot parse (for example a tsconfig.json
#                           with comments makes the whole IaC scan fail).
#         ENRICH            local (default) | github | none
#                             local  = read snippet lines from the clean checkout, no GitHub call
#                             github = fetch lines from GitHub at the commit (GITHUB_TOKEN, GITHUB_API_URL for GHE)
#                             none   = write only the raw CLI outputs and manifest.json (the downstream platform enriches)
#         SKIP_PUSHED_CHECK 1 to skip the "commit exists on the remote" check (only used with ENRICH=github)
#
# Output (in <out_dir>): manifest.json, code.sarif, iac.json, sca.json, enriched.json, enriched.md
#         manifest.json lists the status of each scan: ok | none (nothing to scan) | failed | skipped
# Exit:   0 all scans done, 2 guard failed (dirty workspace, no branch, commit not pushed),
#         3 every scan failed, 4 partial (at least one scan failed, results of the others are in the bundle),
#         5 snippet enrichment failed
#
# Give every scan its own <out_dir> (for example including the commit SHA). Scans share no state,
# so several branches of the same repo can run at the same time.
set -uo pipefail

DIR=${1:?checkout dir}; REPO=${2:?owner/repo}; OUT=${3:?out dir}
HERE=$(cd "$(dirname "$0")" && pwd)
ENRICH=${ENRICH:-local}
ORG=(); [ -n "${SNYK_ORG:-}" ] && ORG=(--org="$SNYK_ORG")
mkdir -p "$OUT" && OUT=$(cd "$OUT" && pwd)
cd "$DIR" || { echo "no such dir: $DIR"; exit 2; }

# 1. Guard: the scan must see exactly what the commit contains, otherwise line numbers will not match.
ROOT=$(git rev-parse --show-toplevel) || { echo "ABORT: not a git checkout"; exit 2; }
PREFIX=$(git rev-parse --show-prefix); PREFIX=${PREFIX%/}      # "" at the repo root, "frontend" in a subfolder
[ -z "$(git status --porcelain)" ] || { echo "ABORT: workspace has changes; scan a clean checkout"; exit 2; }
SHA=$(git rev-parse HEAD)
BRANCH=${BRANCH:-${BRANCH_NAME:-$(git rev-parse --abbrev-ref HEAD)}}
[ "$BRANCH" != HEAD ] || { echo "ABORT: detached HEAD and no BRANCH or BRANCH_NAME set"; exit 2; }
BUILD=${BUILD_ID:-local}
if [ "$ENRICH" = github ] && [ "${SKIP_PUSHED_CHECK:-0}" != 1 ]; then
  git branch -r --contains "$SHA" | grep -q . || { echo "ABORT: $SHA is not on the remote, GitHub cannot serve it"; exit 2; }
fi
echo "[1] clean checkout  repo=$REPO branch=$BRANCH commit=$SHA${PREFIX:+ subfolder=$PREFIX}"

# exit codes of the Snyk CLI: 0 clean, 1 findings, 2 failure, 3 nothing supported to scan
STATUS_CODE=none; STATUS_IAC=none; STATUS_SCA=skipped
run() {  # run <label> <outfile> <cmd...>   sets STATUS_<LABEL>
  local label=$1 file=$2; shift 2
  local up; up=$(echo "$label" | tr a-z A-Z)
  "$@" >"$OUT/$label.out" 2>"$OUT/$label.err"; local c=$?
  case $c in 0|1) echo "[scan] $label done (exit $c)"; eval "STATUS_$up=ok";;
             3)   echo "[scan] $label: nothing to scan"; rm -f "$OUT/$file"; eval "STATUS_$up=none";;
             *)   echo "[scan] $label FAILED (exit $c): $(grep -m1 -i 'error\|fail' "$OUT/$label.out" "$OUT/$label.err" 2>/dev/null | head -1)"
                  rm -f "$OUT/$file"; eval "STATUS_$up=failed";; esac
}

# 2. Scan
run code code.sarif snyk code test ${ORG[@]+"${ORG[@]}"} --sarif-file-output="$OUT/code.sarif"
run iac  iac.json   snyk iac test  ${ORG[@]+"${ORG[@]}"} --json-file-output="$OUT/iac.json" ${IAC_PATHS:-}
if [ -n "${SCA_PREP:-}" ]; then
  if eval "$SCA_PREP" >"$OUT/sca_prep.log" 2>&1; then
    run sca sca.json snyk test ${ORG[@]+"${ORG[@]}"} --json-file-output="$OUT/sca.json" ${SCA_ARGS:-}
  else
    echo "[scan] sca FAILED: SCA_PREP failed, see $OUT/sca_prep.log"; STATUS_SCA=failed
  fi
fi

# 3. Manifest: what the downstream platform needs next to the raw results
CLI_VERSION=$(snyk --version 2>/dev/null | head -1)
python3 -I - "$OUT/manifest.json" "$REPO" "$BRANCH" "$SHA" "$BUILD" "$CLI_VERSION" "$PREFIX" \
  "$STATUS_CODE" "$STATUS_IAC" "$STATUS_SCA" <<'PY'
import json, sys, datetime
out, repo, branch, sha, build, cli, prefix, c, i, s = sys.argv[1:11]
json.dump({"repo": repo, "branch": branch, "commit_id": sha, "build_id": build, "snyk_cli_version": cli,
           "subfolder": prefix, "scans": {"code": c, "iac": i, "sca": s},
           "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")},
          open(out, "w"), indent=1)
PY
echo "[3] manifest written  scans: code=$STATUS_CODE iac=$STATUS_IAC sca=$STATUS_SCA"

# overall result
FAILED=0; for x in $STATUS_CODE $STATUS_IAC $STATUS_SCA; do [ "$x" = failed ] && FAILED=$((FAILED+1)); done
RC=0; [ $FAILED -gt 0 ] && RC=4
[ "$STATUS_CODE" = failed ] && [ "$STATUS_IAC" = failed ] && RC=3

[ "$ENRICH" = none ] && { echo "done (raw results only): $OUT"; exit $RC; }

# 4. Enrich with code snippets. File paths are relative to the repo root, so the subfolder is added as a prefix.
ARGS=(--repo "$REPO" --sha "$SHA" --branch "$BRANCH" --build-id "$BUILD" --out "$OUT/enriched" --path-prefix "$PREFIX")
[ -f "$OUT/code.sarif" ] && ARGS+=(--sarif "$OUT/code.sarif")
[ -f "$OUT/iac.json" ]   && ARGS+=(--iac-json "$OUT/iac.json")
[ -f "$OUT/sca.json" ]   && ARGS+=(--sca-json "$OUT/sca.json" --manifest "${MANIFEST:-package.json}")
[ "$ENRICH" = local ] && ARGS+=(--local-root "$ROOT")
python3 -I "$HERE/enrich_snippets.py" "${ARGS[@]}" || RC=$((RC>0?RC:5))
echo "[4] done: $OUT/enriched.json (exit $RC)"
exit $RC
