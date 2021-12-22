import hashlib

from .ed import EdPoint, G, q, secret_scalar
from .util import sha, toint


def ed_sign(edsk: bytes, msg: bytes) -> bytes:
  """Standard Ed25519 signature"""
  a = secret_scalar(edsk)
  prefix = hashlib.sha512(edsk).digest()[32:]
  A = a * G
  r = sha(prefix + msg) % q
  R = r * G
  Rs = bytes(R)
  h = sha(Rs + bytes(A) + msg) % q
  s = (r + h*a) % q
  return Rs + int.to_bytes(s, 32, "little")

def ed_verify(edpk: bytes, msg: bytes, signature: bytes) -> None:
  """Standard Ed25519 signature verification"""
  if len(signature) != 64:
    Exception("Bad signature length")
  A = EdPoint.from_bytes(edpk)
  if A.is_low_order:
    raise ValueError("Invalid public key provided")
  Rs = signature[:32]
  R = EdPoint.from_bytes(Rs)
  if R.is_low_order:
    raise ValueError("Invalid R point on signature")
  s = toint(signature[32:])
  if s >= q:
    raise ValueError("Invalid s value on signature")
  h = sha(Rs + bytes(A) + msg) % q
  # Finally we confirm that (r + h * a) * G == R + h * A
  if s * G != R + h * A:
    raise ValueError("Signature mismatch")
