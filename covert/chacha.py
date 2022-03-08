from nacl._sodium import ffi, lib
from nacl.exceptions import CryptoError

from typing import Optional
from covert.typing import BytesLike

# The bindings provided in pynacl would only accept bytes (not memoryview etc),
# and did not provide support for allocating the return buffer in Python.


def decrypt(ciphertext: bytes, aad: Optional[bytes], nonce: bytes, key: bytes) -> bytearray:
  message = bytearray(len(ciphertext) - 16)
  if decrypt_into(message, ciphertext, aad, nonce, key):
    raise CryptoError('Decryption failed')
  return message


def encrypt(message: BytesLike, aad: Optional[bytes], nonce: bytes, key: bytes) -> bytes:
  ciphertext = bytearray(len(message) + 16)
  if encrypt_into(ciphertext, message, aad, nonce, key):
    raise CryptoError('Encryption failed')
  return ciphertext


def encrypt_into(ciphertext: bytes, message: BytesLike, aad: Optional[bytes], nonce: bytes, key: bytes) -> int:
  mlen = len(message)
  clen = ffi.new("unsigned long long *")
  ciphertext = ffi.from_buffer(ciphertext)
  message = ffi.from_buffer(message)
  if aad:
    _aad = ffi.from_buffer(aad)
    aalen = len(aad)
  else:
    _aad = ffi.NULL
    aalen = 0

  return lib.crypto_aead_chacha20poly1305_ietf_encrypt(
    ciphertext, clen, message, mlen, _aad, aalen, ffi.NULL, nonce, key
  )


def decrypt_into(message: bytearray, ciphertext: bytes, aad: Optional[bytes], nonce: bytes, key: bytes) -> int:
  clen = len(ciphertext)
  mlen = ffi.new("unsigned long long *")
  message = ffi.from_buffer(message)
  ciphertext = ffi.from_buffer(ciphertext)
  if aad:
    _aad = aad
    aalen = len(aad)
  else:
    _aad = ffi.NULL
    aalen = 0

  return lib.crypto_aead_chacha20poly1305_ietf_decrypt(
    message, mlen, ffi.NULL, ciphertext, clen, _aad, aalen, nonce, key
  )
