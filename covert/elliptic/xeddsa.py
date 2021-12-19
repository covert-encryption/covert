from typing import Optional

from .ed import EdPoint, G, edsk_scalar, q
from .util import clamp, sha, tobytes, toint

# Implements Signal's XEdDSA signature scheme XEd25519
# https://signal.org/docs/specifications/xeddsa/

# Notice that the implementation is mostly in Ed25519 rather than Montgomery,
# although the keys are converted from Curve25519 for this. The public points
# stored in the signatures use the Ed25519 format.

# The sign of the public key in Edwards format is stored into the highest bit
# of s in accordance to what Signal is doing in their source code, despite
# this not being mentioned in specification. Thus, the private scalar a is not
# manipulated at all, as the specification would suggest.

# https://github.com/signalapp/libsignal-client/blob/main/rust/protocol/src/curve/curve25519.rs#L102


def hashn(data: bytes, n: Optional[int] = None) -> int:
  """The domain-separating hash function from specification, mod q"""
  prefix = b"" if n is None else tobytes((1 << 256) - 1 - n)
  return sha(prefix + data) % q

def xed_sign(sk: bytes, message: bytes, nonce: bytes) -> bytes:
  if len(nonce) != 64:
    raise ValueError("A 64-byte random nonce is required")
  # Secret scalars
  a = clamp(toint(sk))
  r = hashn(sk + message + nonce, 1)
  # Public points
  A = a * G
  R = r * G
  # Calculate a signature
  h = hashn(bytes(R) + bytes(A) + message)
  s = (r + h * a) % q | A.sign << 255  # Inject sign into bit 255
  return bytes(R) + tobytes(s)

def xed_verify(pk: bytes, message: bytes, signature: bytes) -> None:
  if len(signature) != 64:
    raise ValueError("Invalid signature length")
  A = EdPoint.from_xbytes(pk)
  # The specs don't require this check (from_xbytes already raises if not on curve)
  if A.is_low_order:
    raise ValueError("Invalid public key provided")
  R, s = EdPoint.from_bytes(signature[:32]), toint(signature[32:])
  # Restore the sign of A from the high bit of s
  sign = s & (1 << 255)
  s ^= sign
  if sign: A = -A
  # Verify the signature
  if R.is_low_order:
    raise ValueError("Invalid R point on signature")
  if s >= q:
    raise ValueError("Invalid s value on signature")
  h = hashn(bytes(R) + bytes(A) + message)
  if R != s * G - h * A:
    raise ValueError("Signature mismatch")
