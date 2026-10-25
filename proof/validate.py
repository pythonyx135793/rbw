"""Read-only validation of one frozen public application commit."""
import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import time
import zipfile
import urllib.request

SOURCE_SHA = "6963a224ef915b9c03574039ee2d507c13fb58d6"
BASE_SHA = "77464d414a9e41165d5b15f049bee1f0c0f2a982"
source, evidence, baseline = (Path(arg).resolve() for arg in sys.argv[1:])
proof = Path(__file__).resolve().parent
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
target_root = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
baseline_target = target_root / "baseline"
candidate_target = target_root / "candidate"
assert baseline_target != candidate_target
results["isolated_target_directories"] = {"baseline": str(baseline_target), "candidate": str(candidate_target)}


def run(name, args, timeout=1200, cwd=None, expected=0):
    start = time.monotonic()
    log = evidence / (name + ".log")
    command_env = os.environ.copy()
    command_env["CARGO_TARGET_DIR"] = str(baseline_target if cwd == baseline else candidate_target)
    try:
        with log.open("wb") as stream:
            proc = subprocess.Popen(args, cwd=cwd or source, env=command_env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        code = 124
    record = {"name": name, "argv": args, "exit": code, "expected_exit": expected, "cargo_target_dir": command_env["CARGO_TARGET_DIR"], "seconds": round(time.monotonic() - start, 3), "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
    results["commands"].append(record)
    (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(record), flush=True)
    if code:
        print(log.read_text(errors="replace")[-12000:], flush=True)
    return code


assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=baseline).decode().strip()==BASE_SHA
run("rust-version", ["rustc", "+1.99.1", "--version"], 30)
results["unchanged_baseline_proof"] = {
    "source": BASE_SHA,
    "run": 40232059047,
    "artifact": 12612968678,
    "archive_sha256": "9bfc3eda8ea4f9696694db8447e0369e0d161df41fc46457465a1d2d3c8dd801",
    "reason": "Same frozen original and toolchain already verified; preserve full lint diagnostics, build and CLI negative control without repeating them."
}
oracle_only = True
results["previous_source_proof"] = {
    "source": SOURCE_SHA,
    "run": 40235445646,
    "artifact": 12615150972,
    "archive_sha256": "a809a50d9d7c6db26d570eef093bfe85baf78b544725fa22df2e24aa0aad52c2",
    "verified": "35 tests passed in each feature mode, format/build/strict Clippy passed, 24 CLI-agent and7 real-server checks passed; oracle process stayed alive after its cleanup report and hit300s.",
    "reason": "Application is unchanged. This run checks fixture connection ownership and actual process termination; successful current source tests are not repeated."
}
binary_root=candidate_target/"debug"
if not oracle_only:
    run("format", ["cargo", "+1.99.1", "fmt", "--check"], 60)
tests = 0 if oracle_only else run("all-feature-tests", ["cargo", "+1.99.1", "test", "--locked", "--all-features"])
if tests == 0:
    if not oracle_only:
        run("no-default-feature-tests", ["cargo", "+1.99.1", "test", "--locked", "--no-default-features"])
    built=run("production-build", ["cargo", "+1.99.1", "build", "--locked", "--all-features"])
    if not oracle_only:
        run("clippy", ["cargo", "+1.99.1", "clippy", "--locked", "--all-targets", "--all-features", "--", "-Dwarnings"])
        run("candidate-clippy-diagnostics", ["cargo", "+1.99.1", "clippy", "--locked", "--all-targets", "--all-features", "--message-format=json"])
    if built==0:
        if not oracle_only:
            run("actual-cli-agent-e2e", ["node",str(proof/"agent-e2e.mjs"),str(binary_root/"rbw"),str(binary_root/"rbw-agent"),str(evidence)], timeout=240)
        oracle=evidence.parent/"bw-oracle"
        install=run("install-official-oracle", ["npm","install","--prefix",str(oracle),"--ignore-scripts","--no-audit","--no-fund","@bitwarden/cli@2025.12.1"], timeout=300)
        pulled=run("pull-vaultwarden", ["docker","pull","vaultwarden/server:1.37.4"], timeout=300)
        if install==0 and pulled==0:
            data=evidence.parent/"vaultwarden-data";data.mkdir(exist_ok=True)
            name="rbw-fixture-"+os.environ["GITHUB_RUN_ID"]
            try:
                started=run("start-vaultwarden",["docker","run","--detach","--name",name,"--user",f"{os.getuid()}:{os.getgid()}","--publish","127.0.0.1:18080:8080","--env","ROCKET_PORT=8080","--env","DOMAIN=https://127.0.0.1:18443","--env","WEB_VAULT_ENABLED=false","--env","SIGNUPS_ALLOWED=true","--mount",f"type=bind,source={data},target=/data","vaultwarden/server:1.37.4"],timeout=60)
                run("vaultwarden-image-identity",["docker","image","inspect","vaultwarden/server:1.37.4"],timeout=30)
                if started==0:
                    deadline=time.monotonic()+40
                    while True:
                        try:
                            urllib.request.urlopen("http://127.0.0.1:18080/alive",timeout=2).close();break
                        except Exception:
                            if time.monotonic()>deadline:raise
                            time.sleep(0.25)
                    run("actual-vaultwarden-oracle-e2e",["node",str(proof/"vaultwarden-e2e.mjs"),str(binary_root/"rbw"),str(binary_root/"rbw-agent"),str(oracle/"node_modules/@bitwarden/cli/build/bw.js"),"http://127.0.0.1:18080",str(evidence)],timeout=300)
            finally:
                run("vaultwarden-log",["docker","logs",name],timeout=30)
                run("cleanup-owned-vaultwarden",["docker","rm","--force",name],timeout=30)
                remaining=subprocess.check_output(["docker","ps","-a","--filter",f"name=^/{name}$","--format","{{.ID}}"])
                results["owned_container_removed"]=not remaining.strip()
                assert results["owned_container_removed"]
results["final_clean_source"] = not git("status", "--porcelain") and all(hashlib.sha256((source / path).read_bytes()).hexdigest() == digest for path, digest in manifest.items())
(evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in evidence.iterdir() if path.is_file()}
(evidence / "artifact-manifest.json").write_text(json.dumps(files, indent=2) + "\n")
assert results["final_clean_source"], "application sources changed during validation"
sys.exit(1 if any(command["exit"] != command["expected_exit"] for command in results["commands"]) else 0)
