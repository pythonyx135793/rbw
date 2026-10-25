"""Read-only validation of one frozen public application commit."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import zipfile

SOURCE_SHA = "ece29f631556ea4a254b99d01325afd7aa23609e"
source, evidence = (Path(arg).resolve() for arg in sys.argv[1:])
evidence.mkdir(parents=True, exist_ok=True)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=source).decode().strip()


assert git("rev-parse", "HEAD") == SOURCE_SHA
assert not git("status", "--porcelain")
paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).decode().split("\0")[:-1]
manifest = {path: hashlib.sha256((source / path).read_bytes()).hexdigest() for path in paths}
with zipfile.ZipFile(evidence / "tested-source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
    for path in paths:
        archive.write(source / path, path)
results = {"source_commit": SOURCE_SHA, "source_tree": git("rev-parse", "HEAD^{tree}"), "source_sha256": manifest, "commands": []}


def run(name, args, timeout=1200):
    start = time.monotonic()
    log = evidence / (name + ".log")
    try:
        with log.open("wb") as stream:
            proc = subprocess.run(args, cwd=source, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        code = 124
    record = {"name": name, "argv": args, "exit": code, "seconds": round(time.monotonic() - start, 3), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
    results["commands"].append(record)
    (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(record), flush=True)
    if code:
        print(log.read_text(errors="replace")[-12000:], flush=True)
    return code


run("rust-version", ["rustc", "+1.99.1", "--version"], 30)
run("format", ["cargo", "+1.99.1", "fmt", "--check"], 60)
tests = run("all-feature-tests", ["cargo", "+1.99.1", "test", "--locked", "--all-features"])
if tests == 0:
    run("no-default-feature-tests", ["cargo", "+1.99.1", "test", "--locked", "--no-default-features"])
    run("production-build", ["cargo", "+1.99.1", "build", "--locked", "--all-features"])
    run("clippy", ["cargo", "+1.99.1", "clippy", "--locked", "--all-targets", "--all-features", "--", "-Dwarnings"])
results["final_clean_source"] = not git("status", "--porcelain") and all(hashlib.sha256((source / path).read_bytes()).hexdigest() == digest for path, digest in manifest.items())
(evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in evidence.iterdir() if path.is_file()}
(evidence / "artifact-manifest.json").write_text(json.dumps(files, indent=2) + "\n")
assert results["final_clean_source"], "application sources changed during validation"
sys.exit(1 if any(command["exit"] for command in results["commands"]) else 0)
