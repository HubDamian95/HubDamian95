#!/usr/bin/env python3
"""
Simple text encrypt/decrypt utility.

Usage:
  Encrypt:
    python3 note_cipher.py encrypt --text "my secret"

  Decrypt:
    python3 note_cipher.py decrypt --token "<base64 token>"

  For Usage: python3 note_cipher.py encrypt --text 'test message' --key ''

For better security store the key in environment variable and invoke it via ENV VAR. 
Created this as I need to encode/decode some data on the daily basis and store it away from website scramblers/AI being able to read my stuff.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VERSION = b"NC1"
SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITERS = 250_000


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_text(passphrase: str, plaintext: str) -> str:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    token = VERSION + salt + nonce + ciphertext
    return base64.urlsafe_b64encode(token).decode("ascii")


def decrypt_text(passphrase: str, token: str) -> str:
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    if len(raw) < len(VERSION) + SALT_LEN + NONCE_LEN + 16:
        raise ValueError("Token is too short or malformed.")
    if raw[: len(VERSION)] != VERSION:
        raise ValueError("Unsupported token version.")
    pos = len(VERSION)
    salt = raw[pos : pos + SALT_LEN]
    pos += SALT_LEN
    nonce = raw[pos : pos + NONCE_LEN]
    pos += NONCE_LEN
    ciphertext = raw[pos:]
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def read_key(cli_key: str | None) -> str:
    if cli_key is not None:
        return cli_key
    key = getpass.getpass("Enter key/passphrase: ")
    if not key:
        raise ValueError("Empty key is not allowed.")
    return key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Encrypt/decrypt text notes.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt plain text to a token")
    p_enc.add_argument("--text", required=True, help="Plain text to encrypt")
    p_enc.add_argument("--key", help="Passphrase/key (avoid in shell history)")

    p_dec = sub.add_parser("decrypt", help="Decrypt token back to plain text")
    p_dec.add_argument("--token", required=True, help="Encrypted token")
    p_dec.add_argument("--key", help="Passphrase/key (avoid in shell history)")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        key = read_key(args.key)
        if args.command == "encrypt":
            print(encrypt_text(key, args.text))
            return 0
        if args.command == "decrypt":
            print(decrypt_text(key, args.token))
            return 0
        parser.error("Unknown command")
        return 2
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
