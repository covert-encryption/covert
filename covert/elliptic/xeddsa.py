from typing import Optional

from .ed import EdPoint, G, q, secret_scalar
from .util import clamp, sha, tobytes, toint, tointsign

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
  s = (r + h * a) % q | A.is_negative << 255  # Inject sign into bit 255
  return bytes(R) + tobytes(s)

def xed_verify(pk: bytes, message: bytes, signature: bytes) -> None:
  if len(signature) != 64:
    raise ValueError("Invalid signature length")
  try:
    A = EdPoint.from_montbytes(pk)
    if A.is_low_order: raise ValueError
  except ValueError:
    raise ValueError("Invalid public key provided")
  try:
    R = EdPoint.from_bytes(signature[:32])
    if R.is_low_order: raise ValueError
  except ValueError:
    raise ValueError("Invalid R point on signature")
  s = toint(signature[32:])
  # Restore the sign of A from the high bit of s
  s, sign = tointsign(s)
  if sign: A = -A
  # Verify the signature
  if s >= q:
    raise ValueError("Invalid s value on signature")
  h = hashn(bytes(R) + bytes(A) + message)
  if R != s * G - h * A:
    raise ValueError("Signature mismatch")
