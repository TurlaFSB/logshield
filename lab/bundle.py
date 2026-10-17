#!/usr/bin/env python3
"""Build the self-contained lab bundle (run this on the HOST, not in the lab VM).

The lab VM (Metasploitable 3 Ubuntu 14.04) has no Java and cannot be trusted to
reach modern TLS endpoints, so everything is fetched and verified here and then
copied to the VM. Standard library only; works on Windows, macOS and Linux.

    python3 lab/bundle.py --out lab-bundle            # download + build + tar
    python3 lab/bundle.py --out lab-bundle --offline  # reuse files already in <out>/downloads

Downloads (each verified against the publisher's own checksum, and the SHA-256
of what we actually got is written to VERSIONS.txt so it can be cross-checked
independently):
  * Eclipse Temurin JDK 8 (linux x64)    sha256 from the Adoptium API
  * log4j-core 2.14.1, log4j-api 2.14.1  sha1 from Maven Central (.sha1 file)

Builds, if `go` is on PATH: static linux/amd64 `labrun` and `logshield`.
Nothing here executes downloaded code.
"""

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import urllib.request

LOG4J_VERSION = "2.14.1"
CENTRAL = "https://repo1.maven.org/maven2/org/apache/logging/log4j"
ADOPTIUM = (
    "https://api.adoptium.net/v3/assets/latest/8/hotspot"
    "?architecture=x64&image_type=jdk&os=linux&vendor=eclipse"
)
REPO = pathlib.Path(__file__).resolve().parent.parent


def fetch(url, dest, timeout=300):
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "logshield-lab-bundle"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def digest(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def get_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "logshield-lab-bundle"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode()


def die(msg):
    print("bundle: " + msg, file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="lab-bundle")
    ap.add_argument(
        "--offline", action="store_true", help="do not download; use <out>/downloads"
    )
    ap.add_argument("--skip-go", action="store_true", help="do not build Go binaries")
    a = ap.parse_args()

    out = pathlib.Path(a.out).resolve()
    dl = out / "downloads"
    stage = out / "logshield-lab"
    if stage.exists():
        shutil.rmtree(stage)
    for d in ("lib", "bin", "src", "corpus"):
        (stage / d).mkdir(parents=True)
    versions = []

    # --- JDK 8 -------------------------------------------------------------
    jdk_name = "jdk8-linux-x64.tar.gz"
    jdk = dl / jdk_name
    if not a.offline:
        meta = json.loads(get_text(ADOPTIUM))
        pkg = meta[0]["binary"]["package"]
        want, link, rel = pkg["checksum"], pkg["link"], meta[0].get("release_name", "?")
        fetch(link, jdk)
        got = digest(jdk, "sha256")
        if got != want:
            die(f"JDK sha256 mismatch: publisher says {want}, got {got}")
        (dl / "jdk.release").write_text(rel + "\n" + link + "\n")
    elif not jdk.exists():
        die(f"--offline but {jdk} is missing")
    rel_txt = (
        (dl / "jdk.release").read_text().split("\n")[0]
        if (dl / "jdk.release").exists()
        else "?"
    )
    shutil.copy(jdk, stage / jdk_name)
    versions.append(
        "jdk      {}  {}  ({})".format(digest(jdk, "sha256"), jdk_name, rel_txt)
    )

    # --- Log4j -------------------------------------------------------------
    for art in ("log4j-core", "log4j-api"):
        name = f"{art}-{LOG4J_VERSION}.jar"
        jar = dl / name
        if not a.offline:
            url = f"{CENTRAL}/{art}/{LOG4J_VERSION}/{name}"
            fetch(url, jar)
            want = get_text(url + ".sha1").split()[0].strip().lower()
            got = digest(jar, "sha1")
            if got != want:
                die(f"{name} sha1 mismatch: Central says {want}, got {got}")
        elif not jar.exists():
            die(f"--offline but {jar} is missing")
        shutil.copy(jar, stage / "lib" / name)
        versions.append(
            "log4j    {}  {}  (sha1 {})".format(
                digest(jar, "sha256"), name, digest(jar, "sha1")
            )
        )

    # --- sources, corpus, scripts -----------------------------------------
    for sub in ("listener", "canary"):
        shutil.copytree(REPO / "lab" / sub, stage / "src" / sub)
    shutil.copytree(REPO / "corpus", stage / "corpus", dirs_exist_ok=True)
    for s in ("setup.sh", "run.sh"):
        shutil.copy(REPO / "lab" / s, stage / s)

    # --- Go binaries ------------------------------------------------------
    commit = (
        subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        or "unknown"
    )
    dirty = subprocess.run(
        ["git", "-C", str(REPO), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if not a.skip_go and shutil.which("go"):
        env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
        for cmd in ("logshield", "labrun"):
            r = subprocess.run(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-ldflags=-s -w",
                    "-o",
                    str(stage / "bin" / cmd),
                    "./cmd/" + cmd,
                ],
                cwd=REPO,
                env=env,
                check=False,
            )
            if r.returncode != 0:
                die(f"go build {cmd} failed")
            versions.append(
                "binary   {}  bin/{} (linux/amd64, commit {})".format(
                    digest(stage / "bin" / cmd, "sha256"), cmd, commit[:12]
                )
            )
    else:
        print(
            "bundle: no Go toolchain (or --skip-go): bin/ is empty; build labrun and logshield for linux/amd64 and add them",
            file=sys.stderr,
        )

    (stage / "VERSIONS.txt").write_text(
        "LogShield lab bundle\ncommit {}{}\n\n{}\n".format(
            commit, " (DIRTY working tree)" if dirty else "", "\n".join(versions)
        )
    )

    # --- manifest + archive ------------------------------------------------
    lines = []
    for p in sorted(stage.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256":
            lines.append(
                "{}  {}".format(digest(p, "sha256"), p.relative_to(stage).as_posix())
            )
    (stage / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")

    tarball = out / "logshield-lab.tar.gz"

    def norm(ti):
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        if ti.isfile() and (
            ti.name.endswith(".sh") or ti.name.startswith("logshield-lab/bin/")
        ):
            ti.mode = 0o755
        return ti

    with tarfile.open(tarball, "w:gz") as t:
        t.add(stage, arcname="logshield-lab", filter=norm)
    print(f"bundle: wrote {tarball}")
    print("bundle: sha256 {}".format(digest(tarball, "sha256")))
    print("\n".join(versions))


if __name__ == "__main__":
    main()
