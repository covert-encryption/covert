import hashlib
from secrets import token_bytes

import nacl.bindings as sodium
from nacl.exceptions import BadSignatureError


def signature(key, message):
  #edpk, edsk = calculate_key_pair(presk)
  return sodium.crypto_sign(message, key.edsk + key.edpk)[:64]


def verify(key, message, signature):
  return sodium.crypto_sign_open(bytes(signature + message), key.edpk)
  # FIXME
  edpk = convert_mont(pk)
  try:
    return sodium.crypto_sign_open(signature + message, edpk)
  except BadSignatureError:
    pass
  # We got the sign flip the wrong way. No worries, just flip it!
  edpk = (int.from_bytes(edpk, 'little') ^ (1 << 255)).to_bytes(32, 'little')
  return sodium.crypto_sign_open(signature + message, edpk)


def calculate_key_pair(presk):
  # Sanity checks
  skhashed = sha512(presk)[:32]
  edpk2, sk = sodium.crypto_sign_seed_keypair(presk)
  assert sk[:32] == presk
  assert sk[32:] == edpk2
  sk = sk[:32]
  # Conversion
  k = int.from_bytes(skhashed, "little")
  edpk = bytearray(sodium.crypto_scalarmult_ed25519_base(skhashed))
  assert edpk == edpk2
  if False:
    s = edpk[31] >> 7
    edpk[31] &= 0x7F
    if s:
      k = -k % q
  return bytes(edpk), k.to_bytes(32, "little")


def convert_mont(pk):
  u = int.from_bytes(pk, "little") % p
  y = (u-1) * modp_inv(u + 1) % p
  return y.to_bytes(32, "little")


def xeddsa_sign(sk, message):
  A, a = calculate_key_pair(sk)
  nonce = token_bytes(64)
  padding = ((1 << 256) - 2).to_bytes(32, 'little')
  r = sha512_modq(padding + a + message + nonce)
  R = sodium.crypto_scalarmult_ed25519_base(r.to_bytes(32, 'little'))
  h = sha512_modq(R + A + message)
  ha = point_mul(h, point_decompress(a))
  s = point_add(point_decompress(R), ha)
  return R + point_compress(s)


def clamp(sk):
  sk = bytearray(sk)
  sk[0] &= 248
  sk[31] &= 127
  sk[31] |= 64
  return bytes(sk)


## First, some preliminaries that will be needed.


def sha512(s):
  return hashlib.sha512(s).digest()


# Base field Z_p
p = 2**255 - 19


def modp_inv(x):
  return pow(x, p - 2, p)


# Curve constant
d = -121665 * modp_inv(121666) % p

# Group order
q = 2**252 + 27742317777372353535851937790883648493


def sha512_modq(s):
  return int.from_bytes(sha512(s), "little") % q


## Then follows functions to perform point operations.

# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z


def point_add(P, Q):
  A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
  B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
  C = 2 * P[3] * Q[3] * d % p
  D = 2 * P[2] * Q[2] % p
  E, F, G, H = B - A, D - C, D + C, B + A
  return (E * F, G * H, F * G, E * H)


# Computes Q = s * Q
def point_mul(s, P):
  Q = (0, 1, 1, 0)  # Neutral element
  while s > 0:
    if s & 1:
      Q = point_add(Q, P)
    P = point_add(P, P)
    s >>= 1
  return Q


def point_equal(P, Q):
  # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
  if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
    return False
  if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
    return False
  return True


## Now follows functions for point compression.

# Square root of -1
modp_sqrt_m1 = pow(2, (p-1) // 4, p)


# Compute corresponding x-coordinate, with low bit corresponding to
# sign, or return None on failure
def recover_x(y, sign):
  if y >= p:
    return None
  x2 = (y*y - 1) * modp_inv(d*y*y + 1)
  if x2 == 0:
    if sign:
      return None
    else:
      return 0

  # Compute square root of x2
  x = pow(x2, (p+3) // 8, p)
  if (x*x - x2) % p != 0:
    x = x * modp_sqrt_m1 % p
  if (x*x - x2) % p != 0:
    return None

  if (x & 1) != sign:
    x = p - x
  return x


# Base point
g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)


def point_compress(P):
  zinv = modp_inv(P[2])
  x = P[0] * zinv % p
  y = P[1] * zinv % p
  return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def point_decompress(s):
  if not isinstance(s, int):
    if len(s) != 32:
      raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
  sign = y >> 255
  y &= (1 << 255) - 1

  x = recover_x(y, sign)
  if x is None:
    return None
  else:
    return (x, y, 1, x * y % p)


## These are functions for manipulating the private key.


def secret_expand(secret):
  if len(secret) != 32:
    raise Exception("Bad size of private key")
  h = sha512(secret)
  a = int.from_bytes(h[:32], "little")
  a &= (1 << 254) - 8
  a |= (1 << 254)
  return (a, h[32:])


def secret_to_public(secret):
  (a, dummy) = secret_expand(secret)
  return point_compress(point_mul(a, G))


"""

## The signature function works as below.


def sign(secret, msg):
  a, prefix = secret_expand(secret)
  A = point_compress(point_mul(a, G))
  r = sha512_modq(prefix + msg)
  R = point_mul(r, G)
  Rs = point_compress(R)
  h = sha512_modq(Rs + A + msg)
  s = (r + h*a) % q
  return Rs + int.to_bytes(s, 32, "little")


## And finally the verification function.


def verify(public, msg, signature):
  if len(public) != 32:
    raise Exception("Bad public key length")
  if len(signature) != 64:
    Exception("Bad signature length")
  A = point_decompress(public)
  if not A:
    return False
  Rs = signature[:32]
  R = point_decompress(Rs)
  if not R:
    return False
  s = int.from_bytes(signature[32:], "little")
  if s >= q: return False
  h = sha512_modq(Rs + public + msg)
  sB = point_mul(s, G)
  hA = point_mul(h, A)
  return point_equal(sB, point_add(R, hA))
"""
