"""检查本地所有引用可达的 Git 对象。只报告对象与规则，不回显匹配内容。"""
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(["git", *args])


rules = {
    "private-key": rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE " + rb"KEY-----",
    "provider-token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}|AKIA[A-Z0-9]{16}|sk-(?:proj-)?[A-Za-z0-9_-]{32,}|xox[baprs]-[\w-]{20,})",
}
sensitive_path = re.compile(rb"(?:^|/)(?:\.env(?:\.local)?|[^/]+\.(?:key|p8|p12|pfx|jks|keystore|mobileprovision|svault|svbak|svmig))$")
commits = git("rev-list", "--all").splitlines()
blobs = set()
findings = set()
for commit in commits:
    for entry in git("ls-tree", "-rz", commit).split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        _, kind, oid = meta.split()
        if kind == b"blob":
            blobs.add(oid)
            if sensitive_path.search(path):
                findings.add((oid.decode(), "sensitive-path"))
for oid in blobs | set(commits):
    body = git("cat-file", "-p", oid)
    for rule, pattern in rules.items():
        if re.search(pattern, body):
            findings.add((oid.decode(), rule))
print(f"可达提交 {len(commits)}，独立文件对象 {len(blobs)}，命中 {len(findings)}")
for finding in sorted(findings):
    print(*finding)
sys.exit(bool(findings))
