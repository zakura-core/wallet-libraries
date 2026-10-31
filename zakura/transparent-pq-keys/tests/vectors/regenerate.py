#!/usr/bin/env python3
"""Check or regenerate public test vectors using OpenSSL, never the Rust crate."""

import argparse
import hashlib
import hmac
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ROOT_LABEL = b"Zcash/TransparentPQ/v2"
MESSAGE = b"PQ wallet lifecycle vector"
CONTEXT = "zakura-pq-keys/test-v1"


def run(openssl, *arguments):
    """Run one bounded reference operation; arguments contain only public test data."""
    return subprocess.run(
        [openssl, *map(str, arguments)],
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout


def origin(parameters, network, account, branch, index):
    return (
        bytes([2, parameters, network])
        + account.to_bytes(4, "big")
        + bytes([branch])
        + index.to_bytes(4, "big")
    )


def make_key(openssl, material, directory, algorithm, public_bytes):
    """Return the public key and temporary OpenSSL key path for public test material."""
    key_path = directory / "public-test-key.pem"
    run(
        openssl, "genpkey", "-algorithm", algorithm,
        "-pkeyopt", "hexseed:" + material.hex(), "-out", key_path,
    )
    public_der = run(openssl, "pkey", "-in", key_path, "-pubout", "-outform", "DER")
    # OpenSSL's SPKI ends in the selected scheme's raw public key. The NIST assertion below checks
    # that this extraction reproduces the published raw public-key encoding.
    return public_der[-public_bytes:], key_path


def sign_and_verify(openssl, key_path, message, context, directory, signature_bytes):
    """Create a deterministic signature and verify it independently before saving."""
    message_path = directory / "message.bin"
    signature_path = directory / "signature.bin"
    public_path = directory / "public.pem"
    message_path.write_bytes(message)
    run(openssl, "pkey", "-in", key_path, "-pubout", "-out", public_path)
    run(
        openssl, "pkeyutl", "-sign", "-rawin", "-inkey", key_path,
        "-in", message_path, "-out", signature_path,
        "-pkeyopt", "context-string:" + context,
        "-pkeyopt", "deterministic:1",
    )
    run(
        openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public_path,
        "-in", message_path, "-sigfile", signature_path,
        "-pkeyopt", "context-string:" + context,
    )
    signature = signature_path.read_bytes()
    if len(signature) != signature_bytes:
        raise ValueError("reference signature has the wrong length")
    return signature


def references(openssl, parameters, suffix, n, signature_bytes):
    """Build key-separation vectors and signatures from fixed, non-secret inputs."""
    algorithm = "SLH-DSA-SHA2-" + suffix
    salt = ("Zcash/PQWallet/" + algorithm + "/v2").encode()
    seed = bytes(range(32))
    cases = [
        ("main_receive_0", seed, origin(parameters, 0, 0, 0, 0)),
        ("main_receive_1", seed, origin(parameters, 0, 0, 0, 1)),
        ("main_change_0", seed, origin(parameters, 0, 0, 1, 0)),
        ("main_account_1", seed, origin(parameters, 0, 1, 0, 0)),
        ("test_receive_0", seed, origin(parameters, 1, 0, 0, 0)),
        ("regtest_receive_0", seed, origin(parameters, 2, 0, 0, 0)),
        ("index_below_high_bit", seed, origin(parameters, 0, 0, 0, 0x7FFF_FFFF)),
        ("index_high_bit", seed, origin(parameters, 0, 0, 0, 0x8000_0000)),
        ("last_index", seed, origin(parameters, 0, 0, 0, 0xFFFF_FFFF)),
        ("last_account", seed, origin(parameters, 0, 0xFFFF_FFFF, 0, 0)),
        ("nontrivial_encoding", seed, origin(parameters, 1, 0x0102_0304, 1, 0x8000_0001)),
        ("long_seed", bytes(range(64)), origin(parameters, 0, 0, 0, 0)),
        ("different_seed", bytes([0xFF]) + seed[1:], origin(parameters, 0, 0, 0, 0)),
    ]
    vectors = []
    with tempfile.TemporaryDirectory(prefix="pq-public-vectors-") as temporary:
        directory = Path(temporary)
        nist_material = (ROOT / f"sha2_{suffix}_nist.seed").read_bytes()
        nist_public, key_path = make_key(openssl, nist_material, directory, algorithm, 2 * n)
        if nist_public != (ROOT / f"sha2_{suffix}_nist.pk").read_bytes():
            raise ValueError("OpenSSL did not reproduce the published NIST public key")
        nist_signature = sign_and_verify(
            openssl, key_path, bytes([42]) * 32, "common/slh-dsa/test", directory, signature_bytes,
        )
        derived_signature = None
        for name, wallet_seed, encoded_origin in cases:
            master = hmac.digest(b"Symmetric key seed", wallet_seed, "sha512")
            root = hmac.digest(master[:32], b"\x00" + ROOT_LABEL, "sha512")[32:]
            material_hex = run(
                openssl, "kdf", "-keylen", str(3 * n), "-kdfopt", "digest:SHA512",
                "-kdfopt", "hexkey:" + root.hex(),
                "-kdfopt", "hexsalt:" + salt.hex(),
                "-kdfopt", "hexinfo:" + encoded_origin.hex(), "HKDF",
            ).decode().replace(":", "").strip()
            material = bytes.fromhex(material_hex)
            if len(material) != 3 * n:
                raise ValueError("reference HKDF output has the wrong length")
            public_key, key_path = make_key(openssl, material, directory, algorithm, 2 * n)
            vectors.append({
                "name": name,
                "seed": wallet_seed.hex(),
                "origin": encoded_origin.hex(),
                "root_hash": hashlib.sha256(root).hexdigest(),
                "material": material.hex(),
                "public_key": public_key.hex(),
            })
            if name == "main_receive_0":
                derived_signature = sign_and_verify(openssl, key_path, MESSAGE, CONTEXT, directory, signature_bytes)
    return {
        f"derivation_{suffix}.json": (json.dumps({"vectors": vectors}, indent=2) + "\n").encode(),
        f"derived_{suffix}_openssl.sig": derived_signature,
        f"sha2_{suffix}_openssl.sig": nist_signature,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default=shutil.which("openssl"))
    parser.add_argument("--write", action="store_true", help="replace generated public fixtures")
    args = parser.parse_args()
    if not args.openssl:
        parser.error("OpenSSL 3.5 or newer is required")
    generated = {}
    for parameters, suffix, n, size in [(1, "128f", 16, 17088), (2, "192s", 24, 16224)]:
        generated.update(references(args.openssl, parameters, suffix, n, size))
    for name, expected in generated.items():
        path = ROOT / name
        if args.write:
            path.write_bytes(expected)
        elif path.read_bytes() != expected:
            raise SystemExit(f"reference mismatch: {name}")
        print(f"{'wrote' if args.write else 'verified'} {name}")


if __name__ == "__main__":
    main()
