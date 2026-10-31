#!/usr/bin/env python3
"""Reject node and wallet-pir dependencies in wallet declarations and fresh consumers."""
import json
import posixpath
from pathlib import Path
import subprocess
import tempfile
import tomllib
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


GITHUB_HOSTS = ("github.com", "www.github.com", "ssh.github.com")


def repository_path(value):
    """Normalize a GitHub repository identity without confusing neighboring hosts."""
    if not value:
        return None
    # Cargo source IDs add git+ and a revision; repository metadata can also
    # use Git's scp-style SSH URL. Parse the host independently of its port.
    value = value.strip().removeprefix("git+")
    # Cargo parses special-scheme URLs as WHATWG URLs, which read a backslash as
    # a slash; urlsplit would otherwise keep it inside the hostname.
    if value.split(":", 1)[0].lower() in ("http", "https"):
        value = value.replace("\\", "/")
    if "://" not in value and ":" in value:
        host, path = value.split(":", 1)
        if host.rsplit("@", 1)[-1].lower().rstrip(".") in GITHUB_HOSTS:
            value = f"ssh://{host}/{path}"
    try:
        parsed = urlsplit(value)
        if unquote(parsed.hostname or "").lower().rstrip(".") not in GITHUB_HOSTS:
            return None
    except ValueError:
        return None
    # Git accepts escaped hostnames and resolves dot segments in HTTP paths.
    # Decode once: double escaping names a different path on GitHub.
    path = posixpath.normpath(unquote(parsed.path).lower()).strip("/")
    return path.removesuffix(".git")


def wallet_pir_owned(value):
    """Recognize current and historical wallet-pir repository identities."""
    return repository_path(value) in {"valargroup/wallet-pir", "zakura-core/wallet-pir"}


def node_owned(value):
    """Reject node repository imports even when a new package name is used."""
    return repository_path(value) == "zakura-core/zakura"


def dependency_reason(name, source, owned, node_packages, repository=None):
    """Return why a package cannot be a wallet dependency, or None."""
    if name in owned or wallet_pir_owned(source) or wallet_pir_owned(repository):
        return f"wallet-pir package {name}"
    if name in node_packages or node_owned(source) or node_owned(repository):
        return f"node package {name}"
    return None


def problems(metadata, owned, node_packages):
    """Inspect all dependency declarations, including inactive optional/dev/target edges."""
    errors = []
    for package in metadata["packages"]:
        name = package["name"]
        reason = dependency_reason(name, package.get("source"), owned, node_packages,
                                   package.get("repository"))
        if reason:
            errors.append(f"{name}: forbidden {reason}")
        for dependency in package.get("dependencies", []):
            reason = dependency_reason(dependency["name"], dependency.get("source"),
                                       owned, node_packages)
            if reason:
                errors.append(f"{name}: dependency on {reason}")
    return errors


def lock_problems(lockfile, owned, node_packages):
    """Check every resolved package, including packages inactive in the current build."""
    errors = []
    for package in tomllib.loads(lockfile.read_text()).get("package", []):
        reason = dependency_reason(package["name"], package.get("source"), owned, node_packages)
        if reason:
            errors.append(f"{lockfile.relative_to(ROOT)}: resolves {reason}")
    return errors


def metadata(manifest, locked=True, no_deps=False):
    command = ["cargo", "metadata", "--format-version", "1", "--all-features", "--manifest-path", str(manifest)]
    if locked:
        command.append("--locked")
    if no_deps:
        command.append("--no-deps")
    return json.loads(subprocess.check_output(command, cwd=ROOT, text=True))


def repository_files(name):
    """Find source-owned manifests or locks without scanning Cargo output directories."""
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z",
         "--", name, f"**/{name}"], cwd=ROOT).split(b"\0")
    return sorted({ROOT / item.decode() for item in names if item and (ROOT / item.decode()).is_file()})


def main():
    policy = tomllib.loads((ROOT / "manifests/sources.toml").read_text())["dependency_boundary"]
    owned, nodes = set(policy["wallet_pir_packages"]), set(policy["node_packages"])
    errors = []
    # Check every checked-in manifest, not just root workspace members: standalone
    # tooling and inactive dependency declarations must obey the same boundary.
    workspaces = set()
    for manifest in repository_files("Cargo.toml"):
        declarations = metadata(manifest, no_deps=True)
        errors.extend(problems(declarations, owned, nodes))
        workspaces.add(Path(declarations["workspace_root"]) / "Cargo.toml")
    for manifest in sorted(workspaces):
        errors.extend(problems(metadata(manifest), owned, nodes))
    for lockfile in repository_files("Cargo.lock"):
        errors.extend(lock_problems(lockfile, owned, nodes))

    # Fresh lockfiles prove downstream resolution independently of repository locks.
    with tempfile.TemporaryDirectory(prefix="wallet-boundary-consumers-") as temporary:
        for kind, dependency in (
            ("wallet", f'zakura-pir-protocol = {{ path = "{ROOT / "zakura/pir-protocol"}", features = ["receiver-crypto"] }}'),
            ("facade-default", f'zakura-wallet-lib = {{ path = "{ROOT / "wallet-lib"}" }}'),
            ("facade-zakura", f'zakura-wallet-lib = {{ path = "{ROOT / "wallet-lib"}", default-features = false, features = ["zakura"] }}'),
        ):
            consumer = Path(temporary) / kind
            (consumer / "src").mkdir(parents=True)
            (consumer / "Cargo.toml").write_text(
                f'[package]\nname = "{kind}-boundary-consumer"\nversion = "0.0.0"\nedition = "2024"\n'
                f'[dependencies]\n{dependency}\n')
            source = ('fn main() { let _ = zakura_pir_protocol::receiver::crypto::RECORD_BYTES; }\n'
                      if kind == "wallet" else "fn main() {}\n")
            (consumer / "src/main.rs").write_text(source)
            errors.extend(problems(metadata(consumer / "Cargo.toml", locked=False), owned, nodes))
            if kind == "wallet" and not errors:
                subprocess.run(["cargo", "check", "--locked", "--manifest-path", str(consumer / "Cargo.toml")],
                               cwd=ROOT, check=True)
    if errors:
        raise SystemExit("wallet dependency boundary failed:\n  " + "\n  ".join(sorted(set(errors))))
    print("verified: wallet manifests, graphs, locks and fresh consumers contain no node or wallet-pir dependency")


if __name__ == "__main__":
    main()
