import hashlib
from typing import Tuple


def clamp(x: int) -> int:
  """Ed25519 standard clamping for scalars (from hashed secret key)"""
  # 256 bits 01[x]000  (using 251 bits of x, masking on/off others)

  # Note that clamped scalars are 0 mod 8 to avoid exposing any bits of the scalar
  # when multiplying a dirty point (public key). The maximum value is about 2**127
  # below 8 * q (the modulo of scalars) so a tiny bit of the whole group remains
  # unused. Scalars are not mod p, which would change 12 of the highest values.
  return x & (1 << 255) - 8 | 1 << 254

def clamp_dirty(x: int) -> int:
  """A dirty clamping function that does not clear the low bits."""
  # Used for creation of dirty points using a dirty generator
  return x & (1 << 255) - 1 | 1 << 254


def toint(x) -> int:
  if isinstance(x, int): return x
  if len(x) != 32: raise ValueError("Should be exactly 32 bytes")
  return int.from_bytes(x, "little")

def tointsign(x) -> Tuple[int, bool]:
  """Separate the 255 bit integer and its high bit as a sign, return both."""
  val =  toint(x)
  sign = val & 1 << 255
  return val ^ sign, bool(sign)

def tobytes(x: int) -> bytes:
  return x.to_bytes(32, "little")

def sha(s) -> int:
  """Return SHA-512 as 512 bit integer"""
  return int.from_bytes(shabytes(s), "little")

def shabytes(s) -> bytes:
  return hashlib.sha512(s).digest()
