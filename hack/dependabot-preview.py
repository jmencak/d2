#!/usr/bin/env python3
"""dependabot-preview.py - report what Dependabot would open a PR for.

Dependabot is a GitHub-hosted service and cannot be executed locally, so this
script replays the gates it applies. It answers two questions:

    which vulnerable dependencies would produce a security PR?
    which outdated dependencies would produce a version PR?

Discovery uses the Go vulnerability database (OSV/vuln.go.dev) against the
modules listed in go.mod - the same corpus govulncheck uses, but evaluated
over the whole module graph instead of one package's import graph. That
matches Dependabot, which does no reachability analysis. `--source
govulncheck` switches to govulncheck (reachability-filtered, and dependent on
which packages build) for comparison.

Gates modelled (see https://docs.github.com/en/code-security):

  security updates
    1. module must be in go.mod / go.sum        (vendor/ contents are ignored)
    2. module must NOT be covered by `replace`  (dependabot-core#6361 skips
                                                 replaced dependencies)
    3. a GitHub Advisory (GHSA) must exist      (the Go vuln DB is often ahead
                                                 of the GitHub mirror)
    4. the advisory must name a patched version
    5. module must not match an `ignore` entry.  Rules that only specify
       `update-types` do not apply to security updates (GitHub docs)

  version updates
    1. open-pull-requests-limit must be > 0
    2. a newer version must exist
    3. module must not be replaced, and must not be ignored for the
       semver level of this update (`ignore.update-types`)

Every rejected finding is printed with its reason, so the gap between
"govulncheck says I am vulnerable" and "Dependabot did nothing" is explicit.

Usage:
    ./dependabot-preview.py                      # scan the current repo
    ./dependabot-preview.py --repo ../csi-operator
    ./dependabot-preview.py --source govulncheck # reachability-filtered view
    ./dependabot-preview.py --offline            # no network; config only
    ./dependabot-preview.py --json               # machine-readable
    ./dependabot-preview.py --strict             # exit 1 if a PR is pending
    ./dependabot-preview.py --dump-config        # show parsed dependabot.yml

Environment:
    GITHUB_TOKEN / GH_TOKEN   raises the GHSA API rate limit (60/h anonymous)
    XDG_CACHE_HOME            where advisory responses are cached for 24h,
                              so repeated runs do not burn the rate limit

Requires: python3 (stdlib only). govulncheck only for --source govulncheck.

Exit codes: 0 = nothing to report, 1 = pending PRs with --strict (or an error).
The script only reads the repository: `go list -m -u` is a query, and nothing
is written to go.mod, go.sum or vendor/.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

GHSA_API = "https://api.github.com/advisories"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"


# ==========================================================================
# dependabot.yml (minimal structural reader - not a full YAML parser)
# ==========================================================================

def _strip_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    idx = line.find(" #")
    return (line[:idx] if idx != -1 else line).rstrip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def parse_dependabot(path: str) -> list[dict]:
    raw = [_strip_comment(l) for l in open(path, encoding="utf-8").read().splitlines()]
    lines = [l for l in raw if l.strip()]

    blocks: list[list[str]] = []
    for line in lines:
        if re.match(r"^\s*-\s+package-ecosystem\s*:", line):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)

    entries = []
    for block in blocks:
        text = "\n".join(block)

        def scalar(key: str, default=None):
            m = re.search(rf"^\s*(?:-\s+)?{re.escape(key)}\s*:\s*(.+?)\s*$", text, re.M)
            return m.group(1).strip().strip("\"'") if m else default

        entry = {
            "ecosystem": scalar("package-ecosystem"),
            "directory": scalar("directory", "/"),
            "limit": int(scalar("open-pull-requests-limit", "5")),
            "ignore": [],
            "groups": [],
        }
        ign = _section(block, "ignore")
        if ign:
            entry["ignore"] = _parse_ignore(ign)
        grp = _section(block, "groups")
        if grp:
            entry["groups"] = _parse_groups(grp)
        entries.append(entry)
    return entries


def _section(block: list[str], key: str) -> str:
    for i, line in enumerate(block):
        m = re.match(rf"^(\s*){re.escape(key)}\s*:\s*$", line)
        if not m:
            continue
        base = len(m.group(1))
        out = []
        for nxt in block[i + 1:]:
            if _indent(nxt) <= base:
                break
            out.append(nxt)
        return "\n".join(out)
    return ""


def _parse_ignore(text: str) -> list[dict]:
    """Parse ignore rules, preserving update-types.

    `ignore.update-types` only filters version updates; security updates are
    still created.  Dropping it here would make a wildcard rule such as
    `- dependency-name: "*"` + `update-types: [semver-major]` suppress every
    dependency in both reports.
    """
    rules: list[dict] = []
    # A new rule starts at each "- dependency-name:" item.
    chunks = re.split(r"(?m)^(?=\s*-\s+dependency-name\s*:)", text)
    for chunk in chunks:
        if not chunk.strip():
            continue
        m = re.search(r"^\s*-\s+dependency-name\s*:\s*(.+?)\s*$", chunk, re.M)
        if not m:
            continue
        rule = {"name": m.group(1).strip().strip("\"'"), "update_types": []}

        # update-types may be an inline list or a block list.
        inline = re.search(r"^\s*update-types\s*:\s*\[(.*?)\]\s*$", chunk, re.M)
        if inline:
            rule["update_types"] = [v.strip().strip("\"'")
                                    for v in inline.group(1).split(",") if v.strip()]
        else:
            block = re.search(r"^(\s*)update-types\s*:\s*$", chunk, re.M)
            if block:
                base = len(block.group(1))
                for line in chunk[block.end():].splitlines():
                    if not line.strip():
                        continue
                    if _indent(line) <= base:
                        break
                    item = re.match(r"^\s*-\s+(.+?)\s*$", line)
                    if item:
                        rule["update_types"].append(item.group(1).strip().strip("\"'"))
        rules.append(rule)
    return rules


def _parse_groups(text: str) -> list[dict]:
    groups: list[dict] = []
    current = None
    base = None
    enclosing = None
    for line in text.splitlines():
        if not line.strip():
            continue
        ind = _indent(line)
        if base is None:
            base = ind
        name = re.match(r"^\s*([\w.-]+)\s*:\s*$", line)
        if ind == base and name and name.group(1) not in ("patterns", "exclude-patterns"):
            current = {"name": name.group(1), "applies_to": None,
                       "patterns": [], "exclude": []}
            groups.append(current)
            enclosing = None
            continue
        if current is None:
            continue
        m = re.match(r"^\s*([\w.-]+)\s*:\s*$", line)
        if m:
            enclosing = m.group(1)
            continue
        m = re.match(r"^\s*applies-to\s*:\s*(.+?)\s*$", line)
        if m:
            current["applies_to"] = m.group(1).strip().strip("\"'")
            continue
        m = re.match(r"^\s*-\s+(.+?)\s*$", line)
        if m:
            val = m.group(1).strip().strip("\"'")
            if enclosing == "exclude-patterns":
                current["exclude"].append(val)
            elif enclosing == "patterns":
                current["patterns"].append(val)
    return groups


# ==========================================================================
# go.mod
# ==========================================================================

def parse_gomod(path: str) -> dict:
    """Return replaced module paths plus the full require set (direct+indirect)."""
    text = open(path, encoding="utf-8").read()
    replaced: set[str] = set()
    requires: dict[str, str] = {}

    in_replace = in_require = False
    for line in text.splitlines():
        s = line.split("//")[0].strip()
        if not s:
            continue
        if s.startswith("replace ("):
            in_replace, in_require = True, False
            continue
        if s.startswith("require ("):
            in_require, in_replace = True, False
            continue
        if s == ")":
            in_replace = in_require = False
            continue

        if in_replace or s.startswith("replace "):
            body = s[len("replace "):] if s.startswith("replace ") else s
            if "=>" in body:
                lhs = body.split("=>")[0].strip().split()
                if lhs:
                    replaced.add(lhs[0])
            continue

        if in_require or s.startswith("require "):
            body = s[len("require "):] if s.startswith("require ") else s
            parts = body.split()
            if len(parts) >= 2:
                requires[parts[0]] = parts[1]

    g = re.search(r"^go\s+(\S+)", text, re.M)
    t = re.search(r"^toolchain\s+go?(\S+)", text, re.M)
    return {"replaced": replaced, "requires": requires,
            "go": g.group(1) if g else None,
            "toolchain": "v" + t.group(1) if t else None}


# ==========================================================================
# semver (sufficient for Go module versions)
# ==========================================================================

_VER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _vtuple(v: str):
    m = _VER.match(v.strip())
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    return (int(major), int(minor), int(patch), pre)


def vcmp(a: str, b: str) -> int:
    ta, tb = _vtuple(a), _vtuple(b)
    if ta is None or tb is None:
        return (a > b) - (a < b)
    for x, y in zip(ta[:3], tb[:3]):
        if x != y:
            return -1 if x < y else 1
    pa, pb = ta[3], tb[3]
    if pa == pb:
        return 0
    if pa is None:
        return 1
    if pb is None:
        return -1
    return -1 if pa < pb else 1


def semver_bump(current: str, latest: str) -> str | None:
    """Dependabot `update-types` label for a version change, if classifiable."""
    a, b = _vtuple(current), _vtuple(latest)
    if a is None or b is None:
        return None
    if b[0] != a[0]:
        return "version-update:semver-major"
    if b[1] != a[1]:
        return "version-update:semver-minor"
    if b[2] != a[2]:
        return "version-update:semver-patch"
    return None


def in_range(version: str, rng: str) -> bool:
    """Evaluate a GHSA vulnerable_version_range such as '>= 0, < 0.60.0'."""
    if not rng or rng.strip() in ("*", ">= 0"):
        return True
    for clause in rng.split(","):
        clause = clause.strip()
        if not clause:
            continue
        m = re.match(r"^(>=|<=|>|<|=)?\s*(.+)$", clause)
        if not m:
            continue
        op, ver = m.group(1) or "=", m.group(2).strip()
        c = vcmp(version, ver)
        if not {">=": c >= 0, ">": c > 0, "<=": c <= 0, "<": c < 0, "=": c == 0}[op]:
            return False
    return True


# ==========================================================================
# vulnerability discovery
# ==========================================================================

class Osv:
    """Query the Go vulnerability database for a set of module versions."""

    def __init__(self, offline: bool = False):
        self.offline = offline
        self._vulns: dict[str, dict] = {}
        self.error = None

    def _post(self, url: str, payload: dict) -> dict:
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "dependabot-preview"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def vuln(self, vid: str) -> dict | None:
        if vid in self._vulns:
            return self._vulns[vid]
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(OSV_VULN + urllib.parse.quote(vid),
                                           headers={"User-Agent": "dependabot-preview"}),
                    timeout=30) as r:
                data = json.load(r)
        except Exception as e:  # noqa: BLE001
            self.error = f"OSV detail lookup failed: {e}"
            return None
        self._vulns[vid] = data
        return data

    def findings(self, requires: dict[str, str],
                 replaced: set[str]) -> list[dict]:
        """[{osv, module, version, fixed}] over the whole require set."""
        if self.offline:
            return []
        mods = [(m, v) for m, v in requires.items() if m not in replaced]
        out: list[dict] = []
        for start in range(0, len(mods), 400):
            chunk = mods[start:start + 400]
            payload = {"queries": [{"version": v, "package": {"name": m, "ecosystem": "Go"}}
                                   for m, v in chunk]}
            try:
                res = self._post(OSV_BATCH, payload)
            except Exception as e:  # noqa: BLE001
                self.error = f"OSV batch query failed: {e}"
                return []
            for (mod, ver), result in zip(chunk, res.get("results") or []):
                for stub in result.get("vulns") or []:
                    vid = stub.get("id")
                    detail = self.vuln(vid)
                    if not detail:
                        continue
                    fixed = _osv_fixed(detail, mod, ver)
                    if fixed:
                        out.append({"osv": vid, "module": mod, "version": ver,
                                    "fixed": fixed,
                                    "aliases": [detail.get("id")] +
                                               list(detail.get("aliases") or [])})
        return out


def _osv_fixed(detail: dict, module: str, current: str) -> str | None:
    """Smallest fixed version greater than `current` for `module`."""
    best = None
    for aff in detail.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != "Go" or pkg.get("name") != module:
            continue
        for rng in aff.get("ranges") or []:
            introduced = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                elif "fixed" in ev:
                    int_ok = introduced in (None, "0") or vcmp(current, introduced) >= 0
                    if int_ok and vcmp(ev["fixed"], current) > 0:
                        if best is None or vcmp(ev["fixed"], best) < 0:
                            best = ev["fixed"]
    return best


def govulncheck_findings(module_dir: str) -> tuple[list[dict], str | None]:
    """Fallback discovery. NOTE: filtered by reachability from one package."""
    exe = shutil.which("govulncheck")
    if not exe:
        sys.exit("error: govulncheck not found for --source govulncheck.\n"
                 "  go install golang.org/x/vuln/cmd/govulncheck@latest")
    pkg = find_package_dir(module_dir) or module_dir
    proc = subprocess.run([exe, "-C", pkg, "-scan=module", "-format=json"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout).strip().splitlines()
        sys.exit(f"error: govulncheck failed: {err[0] if err else 'unknown'}")
    findings, dec, text, i, seen = [], json.JSONDecoder(), proc.stdout, 0, set()
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        if "finding" not in obj:
            continue
        f = obj["finding"]
        trace = f.get("trace") or []
        mod = next((t.get("module") for t in trace if t.get("module")), None)
        ver = next((t.get("version") for t in trace if t.get("module")), None)
        if mod and (mod, f.get("osv")) not in seen:
            seen.add((mod, f.get("osv")))
            findings.append({"osv": f.get("osv"), "module": mod,
                             "version": ver, "fixed": f.get("fixed_version"),
                             "aliases": [f.get("osv")]})
    return findings, os.path.relpath(pkg, module_dir)


def find_package_dir(repo: str) -> str | None:
    skip = {"vendor", "node_modules", "testdata", ".git"}
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in skip and not d.startswith(".")]
        if os.path.relpath(root, repo).count(os.sep) > 3:
            dirs[:] = []
            continue
        if any(f.endswith(".go") and not f.endswith("_test.go") for f in files):
            return root
    return None


# ==========================================================================
# GitHub Advisory Database
# ==========================================================================

def _default_cache_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache")
    return os.path.join(base, "dependabot-preview", "ghsa.json")


class Ghsa:
    """Look up advisories by id.

    Matching is done through the advisory identity carried in the OSV record
    (`id` or `aliases`), not by searching `?affects=<module>`. The search
    endpoint only tells us that *some* advisory exists for a module, which
    cannot distinguish "this CVE is unknown to GitHub" from "this CVE is known
    but has no patched version" - and that distinction decides whether
    Dependabot opens a PR or just an alert.
    """

    CACHE_TTL = 24 * 3600

    def __init__(self, offline: bool = False, use_cache: bool = True):
        self.offline = offline
        self.use_cache = use_cache
        self.cache_path = _default_cache_path()
        self.cache: dict[str, dict | None] = {}
        self.disk: dict[str, dict] = {}
        if use_cache:
            try:
                with open(self.cache_path, encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    self.disk = loaded
            except Exception:  # noqa: BLE001 - cache is optional
                self.disk = {}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        self.headers = {"Accept": "application/vnd.github+json",
                        "User-Agent": "dependabot-preview"}
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.error = None

    def _remember(self, ghsa_id: str, data: dict | None) -> None:
        if not self.use_cache:
            return
        self.disk[ghsa_id] = {"at": time.time(), "data": data}
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.disk, f)
            os.replace(tmp, self.cache_path)
        except Exception:  # noqa: BLE001 - never fail on cache writes
            pass

    def advisory(self, ghsa_id: str) -> dict | None:
        if self.offline:
            return None
        if ghsa_id in self.cache:
            return self.cache[ghsa_id]
        entry = self.disk.get(ghsa_id)
        if entry and time.time() - entry.get("at", 0) < self.CACHE_TTL:
            self.cache[ghsa_id] = entry.get("data")
            return entry.get("data")
        url = f"{GHSA_API}/{urllib.parse.quote(ghsa_id)}"
        try:
            req = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.cache[ghsa_id] = None      # alias points nowhere usable
                self._remember(ghsa_id, None)
                return None
            self.error = f"GHSA API HTTP {e.code} (rate limited? set GITHUB_TOKEN)"
            if entry:
                self.error += "; using cached copy"
                self.cache[ghsa_id] = entry.get("data")
                return entry.get("data")
            return None
        except Exception as e:  # noqa: BLE001
            self.error = f"GHSA API unreachable: {e}"
            if entry:
                self.error += "; using cached copy"
                self.cache[ghsa_id] = entry.get("data")
                return entry.get("data")
            return None
        self.cache[ghsa_id] = data
        self._remember(ghsa_id, data)
        return data

    def target(self, adv: dict, module: str, current: str) -> str | None:
        """Lowest patched version for `module` in this advisory."""
        best = None
        mod_l = module.lower()
        for vuln in adv.get("vulnerabilities") or []:
            pkg = ((vuln.get("package") or {}).get("name") or "").lower()
            if pkg != mod_l:
                # allow subpackages (golang.org/x/net/http2) but not /v2 modules
                if not pkg.startswith(mod_l + "/"):
                    continue
                if re.match(r"^v\d+$", pkg[len(mod_l) + 1:].split("/")[0]):
                    continue
            rng = vuln.get("vulnerable_version_range") or ""
            if not in_range(current, rng):
                continue
            cand = vuln.get("first_patched_version") or _upper_bound(rng)
            if cand and vcmp(cand, current) > 0:
                if best is None or vcmp(cand, best) < 0:
                    best = cand
        return best


def ghsa_id_of(finding: dict) -> str | None:
    """The GHSA identity of an OSV record, if GitHub tracks it."""
    for alias in finding.get("aliases") or []:
        if alias and alias.startswith("GHSA-"):
            return alias
    return None


def _upper_bound(rng: str) -> str | None:
    """Fix version implied by a single `<= X` / `< X` range."""
    m = re.match(r"^\s*<\s*(\S+)\s*$", rng)
    return m.group(1) if m else None


# ==========================================================================
# version updates
# ==========================================================================

def run_go_list(module_dir: str) -> tuple[list[dict], str | None]:
    exe = shutil.which("go")
    if not exe:
        return [], "go not found"
    proc = subprocess.run([exe, "list", "-mod=mod", "-m", "-u", "-json", "all"],
                          cwd=module_dir, capture_output=True, text=True)
    if proc.returncode != 0:
        msg = (proc.stderr or proc.stdout).strip().splitlines()
        return [], msg[0] if msg else "go list failed"
    out, dec, i, mods = proc.stdout, json.JSONDecoder(), 0, []
    while i < len(out):
        while i < len(out) and out[i].isspace():
            i += 1
        if i >= len(out):
            break
        obj, i = dec.raw_decode(out, i)
        upd = obj.get("Update") or {}
        if upd.get("Version"):
            mods.append({"module": obj.get("Path"), "current": obj.get("Version"),
                         "latest": upd.get("Version"),
                         "direct": not obj.get("Indirect"),
                         "replaced": bool(obj.get("Replace"))})
    return mods, None


# ==========================================================================
# reporting helpers
# ==========================================================================

def _local_go_version() -> str | None:
    exe = shutil.which("go")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "env", "GOVERSION"], capture_output=True,
                             text=True, timeout=15).stdout.strip()
    except Exception:  # noqa: BLE001
        return None
    return out.replace("go", "v", 1) if out.startswith("go") else None


def _vk(v: str):
    return _vtuple(v) or (0, 0, 0, None)


def match_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def ignore_matches(module: str, rules: list[dict], kind: str,
                   current: str | None = None, latest: str | None = None) -> bool:
    """Whether an `ignore` rule applies to this update.

    GitHub applies `update-types` to version updates only; a rule that has
    update-types therefore cannot suppress a security update.
    """
    bump = semver_bump(current, latest) if kind == "version" and current and latest else None
    for rule in rules:
        if not match_any(module, [rule["name"]]):
            continue
        if kind == "security" and rule["update_types"]:
            continue
        if rule["update_types"] and bump not in rule["update_types"]:
            continue
        return True
    return False


def pick_group(module: str, groups: list[dict], kind: str) -> str:
    """First matching group; `applies-to` defaults to version-updates."""
    for g in groups:
        applies = g.get("applies_to")
        if kind == "security":
            if applies != "security-updates":
                continue
        elif applies not in (None, "version-updates"):
            continue
        if g["patterns"] and match_any(module, g["patterns"]):
            if g["exclude"] and match_any(module, g["exclude"]):
                continue
            return g["name"]
    return "-"


def count_prs(rows: list[dict]) -> int:
    """Dependabot opens one PR per group, plus one per ungrouped dependency."""
    grouped = {r["group"] for r in rows if r["group"] != "-"}
    return len(grouped) + sum(1 for r in rows if r["group"] == "-")


def table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    return "\n".join([fmt.format(*headers),
                      fmt.format(*["-" * w for w in widths])] +
                     [fmt.format(*r) for r in rows])


# ==========================================================================
# main
# ==========================================================================

def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=".", help="repository root (default: .)")
    ap.add_argument("--source", choices=("auto", "osv", "govulncheck"),
                    default="auto", help="vulnerability discovery source")
    ap.add_argument("--offline", action="store_true",
                    help="skip network lookups (configuration checks only)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-cache", action="store_true",
                    help="do not read/write the advisory cache "
                         "(default: ~/.cache/dependabot-preview/ghsa.json)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when Dependabot would open at least one PR")
    ap.add_argument("--dump-config", action="store_true",
                    help="print the parsed dependabot.yml and exit")
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    cfg = next((os.path.join(repo, ".github", n)
                for n in ("dependabot.yml", "dependabot.yaml")
                if os.path.isfile(os.path.join(repo, ".github", n))), None)
    if not cfg:
        sys.exit(f"error: no .github/dependabot.yml in {repo}\n"
                 "       Dependabot is not enabled for this repository.")

    entries = parse_dependabot(cfg)
    if args.dump_config:
        print(json.dumps(entries, indent=2))
        return 0

    ghsa = Ghsa(offline=args.offline, use_cache=not args.no_cache)
    osv = Osv(offline=args.offline)
    report = {"repo": repo, "config": os.path.relpath(cfg, repo),
              "ecosystems": [], "security": [], "not_actionable": [],
              "version": [], "version_error": None, "warnings": [],
              "toolchain": None}

    for entry in entries:
        sec: dict[str, dict] = {}
        nact: dict[tuple, dict] = {}
        eco = entry["ecosystem"]
        mod_dir = os.path.normpath(os.path.join(repo, entry["directory"].lstrip("/")))
        gomod = os.path.join(mod_dir, "go.mod")
        info = {"ecosystem": eco, "directory": entry["directory"],
                "limit": entry["limit"], "manifest": None, "replaced": 0}
        report["ecosystems"].append(info)

        if eco != "gomod" or not os.path.isfile(gomod):
            info["skipped"] = ("not modelled by this script" if eco != "gomod"
                               else "no go.mod here")
            continue

        mod = parse_gomod(gomod)
        info["manifest"] = os.path.relpath(gomod, repo)
        info["replaced"] = len(mod["replaced"])

        # ---- discovery -------------------------------------------------
        source = args.source
        if source == "auto":
            source = "osv"
        pkg_used = None
        if source == "osv":
            findings = osv.findings(mod["requires"], mod["replaced"])
        else:
            findings, pkg_used = govulncheck_findings(mod_dir)
        if source == "osv" and osv.error:
            report["warnings"].append(osv.error + " - falling back to govulncheck")
            findings, pkg_used = govulncheck_findings(mod_dir)
            source = "govulncheck (fallback)"
        info["source"] = (f"{source} (package {pkg_used})" if pkg_used else source)
        if pkg_used:
            report["warnings"].append(
                "govulncheck module scans are scoped to the loaded package's "
                "import graph, so results are a subset of the full module list")

        # ---- Go toolchain (never a Dependabot PR) -----------------------
        gover = mod["toolchain"] or _local_go_version() or \
            (("v" + mod["go"]) if mod["go"] else None)
        if gover and not args.offline:
            tc = osv.findings({"stdlib": gover.lstrip("v")}, set())
            if tc:
                report["toolchain"] = {
                    "declared": gover,
                    "findings": len(tc),
                    "minimum_fixed": max((f["fixed"] for f in tc), key=_vk),
                }

        # ---- security --------------------------------------------------
        for f in findings:
            module, osv_id = f["module"], f["osv"]
            if module == "stdlib":
                continue
            reason = None
            if module in mod["replaced"]:
                reason = "pinned by a `replace` directive"
            elif ignore_matches(module, entry["ignore"], "security"):
                reason = "matched by an `ignore` entry"

            if reason is None:
                ghsa_id = ghsa_id_of(f)
                if not ghsa_id:
                    reason = "not in the GitHub Advisory Database"
                else:
                    adv = ghsa.advisory(ghsa_id)
                    if adv is None:
                        reason = ("GHSA lookup unavailable (offline / rate limited)"
                                  if ghsa.error else
                                  "not in the GitHub Advisory Database")
                    else:
                        target = ghsa.target(adv, module, f["version"] or "")
                        if not target:
                            reason = "GHSA advisory has no patched version"

            if reason:
                key = (module, reason)
                rec = nact.setdefault(key, {"module": module, "reason": reason,
                                            "osv": [], "fixed": f.get("fixed")})
                rec["osv"].append(osv_id)
                continue

            rec = sec.setdefault(module, {"module": module,
                                          "current": f["version"],
                                          "advisories": set(),
                                          "target": target,
                                          "group": pick_group(module, entry["groups"],
                                                              "security")})
            rec["advisories"].add(ghsa_id)
            if vcmp(target, rec["target"]) > 0:
                rec["target"] = target

        report["security"].extend(
            {**r, "advisories": sorted(r["advisories"])} for r in sec.values())
        report["not_actionable"].extend(nact.values())

        # ---- version updates -------------------------------------------
        if entry["limit"] > 0 and not args.offline:
            mods, err = run_go_list(mod_dir)
            if err:
                report["version_error"] = err
            for m in mods:
                if not m["module"] or m["replaced"]:
                    continue
                if ignore_matches(m["module"], entry["ignore"], "version",
                                  m["current"], m["latest"]):
                    continue
                report["version"].append({
                    "module": m["module"], "current": m["current"],
                    "latest": m["latest"], "direct": m["direct"],
                    "group": pick_group(m["module"], entry["groups"], "version")})

    if args.json:
        print(json.dumps(report, indent=2))
        return 1 if (args.strict and report["security"]) else 0

    # ---- human output ---------------------------------------------------
    print(f"repo     : {report['repo']}")
    print(f"config   : {report['config']}")
    for e in report["ecosystems"]:
        mode = ("security-only (open-pull-requests-limit: 0)"
                if e["limit"] == 0
                else f"version + security (open-pull-requests-limit: {e['limit']})")
        print(f"ecosystem: {e['ecosystem']}  dir {e['directory']}  ->  {mode}")
        if e.get("manifest"):
            print(f"manifest : {e['manifest']}  "
                  f"({e['replaced']} replaced module(s) excluded)")
            print(f"discovery: {e.get('source')}")
        if e.get("skipped"):
            print(f"           skipped: {e['skipped']}")
    for w in report["warnings"]:
        print(f"warning  : {w}")
    if ghsa.error:
        print(f"warning  : {ghsa.error}")

    modelled = [e for e in report["ecosystems"] if e.get("manifest")]
    if not modelled:
        print("\nSECURITY UPDATES - not applicable (no gomod manifest modelled)")
        print("VERSION UPDATES  - not applicable (no gomod manifest modelled)")
        print("\nVerdict: 0 modelled ecosystem(s); nothing to report.")
        return 0

    incomplete = " [INCOMPLETE - GHSA lookups failed]" if ghsa.error else ""
    print(f"\nSECURITY UPDATES - Dependabot would open "
          f"{len(report['security'])} PR(s){incomplete}")
    def _adv(r):
        a = r["advisories"]
        return a[0] + (f" +{len(a) - 1}" if len(a) > 1 else "")

    def _v(v):
        return v if not v or v.startswith("v") else "v" + v

    print(table(["module", "current", "advisory", "patched", "group"],
                [[r["module"], r["current"], _adv(r),
                  _v(r["target"]), r["group"]] for r in report["security"]])
          or "  (none)")

    if report["toolchain"]:
        t = report["toolchain"]
        print(f"\nGO TOOLCHAIN - {t['findings']} stdlib finding(s); not a module, "
              f"so Dependabot cannot open a PR")
        print(f"  toolchain in use   : {t['declared']}")
        print(f"  minimum fixed      : go{t['minimum_fixed']}  "
              f"(bump build_root_image / Dockerfile)")

    if report["not_actionable"]:
        print(f"\nNOT ACTIONABLE - vulnerable but Dependabot will not act "
              f"({len(report['not_actionable'])})")
        agg: dict[str, dict] = {}
        for r in report["not_actionable"]:
            a = agg.setdefault(r["reason"], {"n": 0, "mods": set()})
            a["n"] += len(r["osv"])
            a["mods"].add(r["module"])
        rows = []
        for reason, a in sorted(agg.items(), key=lambda kv: -kv[1]["n"]):
            names = sorted(a["mods"])
            shown = ", ".join(names[:3]) + (" ..." if len(names) > 3 else "")
            rows.append([str(a["n"]), reason, shown])
        print(table(["advisories", "reason", "modules"], rows))

    if report["version"] or report["version_error"]:
        print(f"\nVERSION UPDATES - Dependabot would open {len(report['version'])} PR(s)")
        if report["version_error"]:
            print(f"  could not query newer versions: {report['version_error']}")
        rows = [[r["module"], r["current"], r["latest"],
                 "direct" if r["direct"] else "indirect", r["group"]]
                for r in report["version"]]
        shown = rows[:40]
        print(table(["module", "current", "latest", "kind", "group"], shown))
        if len(rows) > len(shown):
            print(f"  ... {len(rows) - len(shown)} more dependency update(s)")
    elif all(e["limit"] == 0 for e in modelled):
        print("\nVERSION UPDATES - disabled (open-pull-requests-limit: 0)")
    else:
        print("\nVERSION UPDATES - none pending")

    sec_prs = count_prs(report["security"])
    ver_prs = count_prs(report["version"])
    caps = [e["limit"] for e in modelled if e["limit"] > 0]
    caveat = " (lower bound)" if ghsa.error else ""
    print(f"\nVerdict: {sec_prs} security PR(s) + {ver_prs} version update(s) "
          f"-> {sec_prs + ver_prs} pull request(s) in total{caveat}.")
    if caps:
        print(f"         open-pull-requests-limit: {min(caps)} caps concurrent "
              f"version PRs; security PRs have a separate fixed cap of 10.")
    if args.offline:
        print("Note: --offline, so vulnerability lookups were skipped.")
    return 1 if (args.strict and (sec_prs + ver_prs)) else 0


if __name__ == "__main__":
    sys.exit(main())
