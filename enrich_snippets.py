#!/usr/bin/env python3
"""Add code snippets to Snyk CLI results by fetching the files from GitHub at the scanned commit.

Input : snyk code test --sarif, snyk iac test --json, snyk test --json (any combination)
Output: enriched JSON + a markdown report (finding, snippet with the flagged lines marked)

Snyk CLI output has locations only. This tool pins every location to a commit SHA and
fetches that file version from GitHub (github.com or GitHub Enterprise), so the lines
always match what was scanned.

Stdlib only. Token: GITHUB_TOKEN, else `gh auth token`.
GitHub Enterprise: --api-url https://<ghe-host>/api/v3
No GitHub access from the runner: --local-root <clean checkout> reads the same files from disk.
"""
import argparse, base64, hashlib, json, os, subprocess, sys, urllib.error, urllib.parse, urllib.request


def token():
    t = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if t:
        return t
    try:
        return subprocess.check_output(["gh", "auth", "token"], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


class Fetcher:
    """Fetch file content at a pinned SHA. One request per file, cached."""

    def __init__(self, api, repo, sha, tok):
        self.api, self.repo, self.sha, self.tok = api.rstrip("/"), repo, sha, tok
        self.cache, self.requests = {}, 0

    def lines(self, path):
        if path in self.cache:
            return self.cache[path]
        url = f"{self.api}/repos/{self.repo}/contents/{urllib.parse.quote(path)}?ref={self.sha}"
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github.raw+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Authorization": f"Bearer {self.tok}"} if self.tok else {}),
        })
        self.requests += 1
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read().decode("utf-8", errors="replace")
            out = data.splitlines()
        except urllib.error.HTTPError as e:
            out = None
            print(f"warn: {path}@{self.sha[:7]} -> HTTP {e.code}", file=sys.stderr)
        self.cache[path] = out
        return out


class LocalFetcher:
    """Same interface, reads the files from a clean checkout on disk (no GitHub call)."""

    def __init__(self, root):
        self.root, self.cache, self.requests = root, {}, 0

    def lines(self, path):
        if path not in self.cache:
            p = os.path.join(self.root, path)
            self.cache[path] = (open(p, encoding="utf-8", errors="replace").read().splitlines()
                                if os.path.isfile(p) else None)
        return self.cache[path]


def snippet(lines, start, end, ctx):
    """Return [{n, text, flagged}] for start..end plus ctx lines either side."""
    if not lines or start is None:
        return None
    end = end or start
    lo, hi = max(1, start - ctx), min(len(lines), end + ctx)
    if start > len(lines):
        return None  # file at this SHA is shorter than the reported line: wrong SHA or modified workspace
    return [{"n": n, "text": lines[n - 1], "flagged": start <= n <= end} for n in range(lo, hi + 1)]


def code_hash(lines, start, end):
    """Hash of the flagged lines with whitespace removed: survives line shifts and re-indentation."""
    if not lines or start is None:
        return None
    body = "".join("".join(lines[start - 1:(end or start)]).split())
    return hashlib.sha256(body.encode()).hexdigest()[:16]


def anchor_ok(f, snip):
    """Sanity check that the snippet really is what Snyk scanned (catches a wrong SHA or a modified workspace).
    IaC: a name from the resource path (attribute, resource type or resource name) must appear in the flagged line.
    SAST: the flagged line must be at least as long as the reported end column."""
    if not snip:
        return False
    flagged = [l["text"] for l in snip if l["flagged"]]
    if f["kind"] == "sca":
        return any(manifest_match(os.path.basename(f["file"]), t, f["locate"]) for t in flagged)
    if f["kind"] == "iac":
        # accept the attribute (present but wrong) or the resource type/name (attribute missing:
        # Snyk then points at the resource header line)
        import re
        toks = [t for t in re.split(r"[.\[\]]", f.get("resource_path") or "") if t and t not in ("resource", "input", "spec")]
        return any(t in line for t in toks for line in flagged)
    return bool(flagged) and (f.get("end_col") is None or len(flagged[-1]) + 1 >= f["end_col"])


def prefixed(path, prefix):
    return f"{prefix.strip('/')}/{path}" if prefix else path


def parse_sarif(doc, prefix):
    out = []
    for run in doc.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            loc = res["locations"][0]["physicalLocation"]
            reg = loc["region"]
            flow = []
            for cf in res.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    for step in tf.get("locations", []):
                        pl = step["location"]["physicalLocation"]
                        flow.append({"file": prefixed(pl["artifactLocation"]["uri"], prefix),
                                     "start": pl["region"]["startLine"],
                                     "end": pl["region"].get("endLine", pl["region"]["startLine"])})
                    break
                break
            out.append({
                "kind": "sast",
                "rule": res["ruleId"],
                "title": rules.get(res["ruleId"], {}).get("shortDescription", {}).get("text", res["ruleId"]),
                "severity": res.get("level"),
                "message": res["message"]["text"],
                "file": prefixed(loc["artifactLocation"]["uri"], prefix),
                "start": reg["startLine"], "end": reg.get("endLine", reg["startLine"]),
                "end_col": reg.get("endColumn") if reg.get("endLine", reg["startLine"]) == reg["startLine"] else None,
                "snyk_id": res.get("fingerprints", {}).get("snyk/asset/finding/v1"),
                "flow": flow,
            })
    return out


def parse_iac(doc, prefix):
    out = []
    for proj in (doc if isinstance(doc, list) else [doc]):
        for i in proj.get("infrastructureAsCodeIssues", []):
            out.append({
                "kind": "iac",
                "rule": i["id"],
                "title": i["title"],
                "severity": i["severity"],
                "message": i.get("msg") or i.get("issue"),
                "file": prefixed(proj["targetFile"], prefix),
                "start": i["lineNumber"], "end": i["lineNumber"],  # IaC gives one line only
                "resource_path": ".".join(str(p) for p in i.get("path", [])),
                "resolve": i.get("resolve"),
                "snyk_id": None,
                "flow": [],
            })
    return out


def parse_sca(doc, prefix, manifest):
    """snyk test --json. No line numbers exist: the location is the line that declares the top-level dependency."""
    out = []
    for proj in (doc if isinstance(doc, list) else [doc]):
        for v in proj.get("vulnerabilities", []):
            top = v["from"][1] if len(v["from"]) > 1 else v["from"][0]
            out.append({
                "kind": "sca", "rule": v["id"], "title": f'{v["title"]} in {v["packageName"]}@{v["version"]}',
                "severity": v["severity"],
                "message": f'Dependency path: {" > ".join(v["from"])}. Fixed in: {", ".join(v.get("fixedIn") or []) or "no fix"}.',
                "file": prefixed(manifest, prefix), "start": None, "end": None,
                "locate": top.rsplit("@", 1)[0],          # top-level dependency name to find in the manifest
                "resource_path": " > ".join(v["from"]),   # used in the key
                "snyk_id": v["id"], "flow": [],
            })
    return out


def manifest_match(base, line, name):
    """Does this manifest line declare dependency `name`? Handles package.json, requirements.txt, go.mod, pom.xml."""
    import re
    t = line.strip()
    if base == "package.json":
        return t.startswith(f'"{name}"')
    if base.startswith("requirements") and base.endswith(".txt"):
        norm = lambda x: re.sub(r"[-_.]+", "-", x).lower()
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", t)
        return bool(m) and norm(m.group(1)) == norm(name)
    if base == "go.mod":
        return t.startswith(name + " ") or t.startswith("require " + name + " ")
    if base == "pom.xml":
        artifact = name.split(":")[-1]
        return f"<artifactId>{artifact}</artifactId>" in t
    return name in t  # unknown manifest: plain text match


def locate(lines, name, base="package.json"):
    """Line number where the manifest declares the dependency."""
    for n, l in enumerate(lines or [], 1):
        if manifest_match(base, l, name):
            return n
    return None


def finding_key(repo, f, h, occ=0):
    """Composite key a downstream platform can use. SAST: rule + file + flagged-code hash (line-shift safe).
    IaC: rule + file + resource path (Snyk gives no ID)."""
    # occ separates identical findings (same rule, same file, same code, e.g. repeated test passwords).
    # It counts by line order, so it stays stable when the whole block moves.
    basis = [repo, f["rule"], f["file"], f["resource_path"] if f["kind"] in ("iac", "sca") else h, occ]
    return hashlib.sha256("|".join(str(b) for b in basis).encode()).hexdigest()[:20]


def render(findings, repo, sha, ctx):
    md = [f"# Snyk findings with code snippets\n", f"Repo `{repo}` at commit `{sha}`. {len(findings)} findings.\n"]
    for n, f in enumerate(findings, 1):
        md.append(f"## {n}. [{f['severity']}] {f['title']}  \n`{f['file']}:{f['start']}`"
                  + (f"  resource `{f['resource_path']}`" if f.get("resource_path") else "")
                  + f"  key `{f['key']}`\n")
        md.append(f"{f['message']}\n")
        if f["snippet"] and not f["anchor_ok"]:
            md.append("**WARNING: snippet does not match the reported finding. Wrong SHA or modified workspace.**\n")
        md.append("```")
        if f["snippet"]:
            for l in f["snippet"]:
                md.append(f"{'>' if l['flagged'] else ' '} {l['n']:>4} | {l['text']}")
        else:
            md.append("(snippet unavailable)")
        md.append("```\n")
        if f["flow"]:
            md.append("Data flow: " + " -> ".join(f"{s['file'].split('/')[-1]}:{s['start']}" for s in f["flow"]) + "\n")
    return "\n".join(md)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", required=True, help="owner/name on GitHub")
    ap.add_argument("--sha", required=True, help="commit that was scanned (capture with git rev-parse HEAD at checkout)")
    ap.add_argument("--branch", default="", help="branch that was scanned (recorded on every finding)")
    ap.add_argument("--build-id", default="", help="CI build id (recorded on every finding)")
    ap.add_argument("--local-root", metavar="DIR", help="read files from this clean checkout instead of GitHub")
    ap.add_argument("--sarif", help="snyk code test --sarif output")
    ap.add_argument("--iac-json", help="snyk iac test --json output")
    ap.add_argument("--sca-json", help="snyk test --json output")
    ap.add_argument("--manifest", default="package.json", help="manifest that declares the dependencies (SCA snippets)")
    ap.add_argument("--path-prefix", default="", help="repo subfolder the CLI was run from (monorepos)")
    ap.add_argument("--context", type=int, default=3, help="lines of context either side")
    ap.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    ap.add_argument("--verify-local", metavar="DIR", help="checkout of the same SHA: compare every fetched file with local bytes")
    ap.add_argument("--out", default="enriched", help="output prefix (.json and .md)")
    ap.add_argument("--limit", type=int, default=0, help="only enrich first N findings per type (0 = all)")
    a = ap.parse_args()

    findings = []
    if a.sarif:
        s = parse_sarif(json.load(open(a.sarif)), a.path_prefix)
        findings += s[:a.limit] if a.limit else s
    if a.iac_json:
        i = parse_iac(json.load(open(a.iac_json)), a.path_prefix)
        findings += i[:a.limit] if a.limit else i

    if a.sca_json:
        c = parse_sca(json.load(open(a.sca_json)), a.path_prefix, a.manifest)
        findings += c[:a.limit] if a.limit else c

    fx = LocalFetcher(a.local_root) if a.local_root else Fetcher(a.api_url, a.repo, a.sha, token())
    missing = suspect = 0
    seen = {}
    for f in sorted(findings, key=lambda x: (x["file"], x["start"] or 0, x["rule"])):
        ls = fx.lines(f["file"])
        if f["kind"] == "sca":
            f["start"] = f["end"] = locate(ls, f["locate"], os.path.basename(f["file"]))
        f["snippet"] = snippet(ls, f["start"], f["end"], a.context)
        f["code_hash"] = code_hash(ls, f["start"], f["end"])
        base = (f["rule"], f["file"], f["resource_path"] if f["kind"] in ("iac", "sca") else f["code_hash"])
        occ = seen[base] = seen.get(base, -1) + 1
        f["key"] = finding_key(a.repo, f, f["code_hash"], occ)
        for step in f["flow"]:  # data-flow steps get a one-line snippet each
            sl = fx.lines(step["file"])
            step["snippet"] = snippet(sl, step["start"], step["end"], 0)
        f["repo"], f["branch"], f["commit_id"], f["build_id"] = a.repo, a.branch, a.sha, a.build_id
        f["finding_id"] = f"{a.repo}|{a.branch}|{f['snyk_id'] or f['key']}"  # repo + branch + Snyk key (falls back to our key for IaC/SCA)
        f["anchor_ok"] = anchor_ok(f, f["snippet"])
        if not f["snippet"]:
            missing += 1
        elif not f["anchor_ok"]:
            suspect += 1

    json.dump({"repo": a.repo, "branch": a.branch, "sha": a.sha, "build_id": a.build_id, "findings": findings}, open(a.out + ".json", "w"), indent=1)
    open(a.out + ".md", "w").write(render(findings, a.repo, a.sha, a.context))

    print(f"findings: {len(findings)}  snippets ok: {len(findings) - missing - suspect}  missing: {missing}  suspect (code does not match what Snyk reported): {suspect}")
    print(f"unique files read: {len(fx.cache)}  GitHub requests: {fx.requests}")

    if a.verify_local:
        same = diff = 0
        for path, ls in fx.cache.items():
            p = os.path.join(a.verify_local, path)
            if ls is None or not os.path.exists(p):
                diff += 1
                continue
            local = open(p, encoding="utf-8", errors="replace").read().splitlines()
            if local == ls:
                same += 1
            else:
                diff += 1
                print(f"MISMATCH {path}")
        print(f"verify-local: {same} files identical to the local checkout, {diff} differ or missing")
        sys.exit(0 if diff == 0 and missing == 0 and suspect == 0 else 1)


if __name__ == "__main__":
    main()
