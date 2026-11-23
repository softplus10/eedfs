#!/usr/bin/env python3
"""Regenerate independent known answers using system libsodium and libargon2.
Requires these C libraries, not Python packages or the Rust implementation.
"""
import ctypes
import ctypes.util
from pathlib import Path

sodium = ctypes.CDLL(ctypes.util.find_library("sodium") or "libsodium.so.26")
argon = ctypes.CDLL(ctypes.util.find_library("argon2") or "libargon2.so.1")
sodium.sodium_init()
sodium.sodium_version_string.restype = ctypes.c_char_p
key, nonce = bytes(range(32)), bytes(range(24))
message = b"EEDFS independent vector"
aad = b"filesystem/object/context"
out = ctypes.create_string_buffer(len(message) + 16)
length = ctypes.c_ulonglong()
status = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    out, ctypes.byref(length), message, ctypes.c_ulonglong(len(message)),
    aad, ctypes.c_ulonglong(len(aad)), None, nonce, key,
)
assert status == 0
argon.argon2id_hash_raw.argtypes = [ctypes.c_uint32] * 3 + [ctypes.c_void_p, ctypes.c_size_t] * 3
kdf = ctypes.create_string_buffer(32)
assert argon.argon2id_hash_raw(1, 8192, 1, b"password", 8, bytes([7]) * 16, 16, kdf, 32) == 0
path = Path(__file__).resolve().parents[1] / "tests/fixtures/crypto-vectors.txt"
path.write_text(
    f"# Generated with libsodium {sodium.sodium_version_string().decode()} and libargon2; inputs in tests/crypto.rs.\n"
    + out.raw[:length.value].hex() + "\n" + kdf.raw.hex() + "\n"
)
