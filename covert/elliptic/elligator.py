# Elligator2 over Curve25519, see section 5 of
# https://www.shiftleft.org/papers/elligator/elligator.pdf

## Why it is extremely difficult to make indistinguishible from random keys

# Curve25519 public key is the u-coordinate of a point representing the key.
# It is a value up to p - 1 (so it fits neatly in 255 bits). Not all values
# are used in standard public keys because
# - The 256th bit is always zero (bitmask to check)
# - Only half of all u values are valid points (curve equation to check)
# - Only 1/8 of the valid points are used in standard public keys (subgroup)
#
# These properties can be easily tested, with only 3 % probability (1/32) of
# that data being just 32 random bytes rather than a standard key.
#
# Any unused high bits can easily be filled with random bits, solving the
# first problem.
#
# Elligator 2 solves the second problem, producing 254 bit values, of which
# practically all are used by valid points. The high bits can be filled with
# random values to make it a 32-byte sequence indistinguishible from random.
#
# Only half of the *valid* u coordinates can be encoded by Elligator 2 at all,
# so in practice we need to try and create key pairs until a public key that
# can be hashed is found.
#
# A quick entropy calculation: the u value is 255 bits minus one for non-points
# and another for non-hashable points. So, Elligator encodes 253 bits worth of
# u coordinate. Why is the value then 254 bits? Because it can also encode
# a sign bit. A sign that is never used with Curve25519 but that exists anyway
# and that won't affect the all-important u coordinate, but that will
# completely mix the Elligator output (not only one bit of it).
#
# All good until now, except that the adversary can still mask out the high
# bits, unhash the Elligator 2 and obtain a curve point. Now, if he multiplies
# that point by q, it reduces to one of the eight *low order points* there are
# in Curve25519. Standard public keys all reduce to big flat ZERO, where any
# random point has equal chance of being in any of the eight sub groups, each
# represented by its own low order point.
#
# The third problem needs to be solved by custom key generation that creates
# *dirty points*, public keys that can be in any sub group, rather than only
# in the prime group.
#
# We can make a point dirty by adding to it a random low point. This does not
# affect the result of standard ECDH using that key, as any subgroups are
# cancelled by the multiplication in those (because the secret scalars are
# multiples of eight after the standard clamping required by the protocols)

## High level API

# Designed around Ed25519 because edsk can be easily converted into Montgomery
# but the opposite is not possible. Also, starting with Ed25519 we have useful
# extra bits to randomise the points, without having to create random numbers.
# Curve25519 sk are already clamped, losing those crucial three low bits.

# The sign of Ed25519 (lowest bit of x) is used as Elligator 2 "v sign", to
# avoid having to calculate the v coordinate (which is rarely used anywhere),
# but to still allow recovering the original Ed25519 public key exactly.

from contextlib import suppress
from secrets import token_bytes
from typing import Tuple

from .ed import LO, EdPoint, G, dirty_scalar
from .mont import A
from .scalar import fe, one, p, sqrtm1, zero
from .util import sha, tobytes, toint


class ElligatorError(ValueError):
  """Point is incompatible with Elligator hashing"""

def egcreate() -> Tuple[bytes, bytes]:
  """
  Create a random hidden key.
  - Compatible with all of Ed25519, Curve25519 and Elligator2
  - 254 bits of entropy (253 for Curve25519)

  :returns: (hidden, edsk)
  """
  while True:
    # Try until successful, half of our attempts should fail
    with suppress(ElligatorError):
      edsk = token_bytes(32)
      return eghide(edsk), edsk

def eghide(edsk: bytes) -> bytes:
  """
  Convert Ed25519 secret key into a random-looking 32-byte string.
  - Deterministic, depends only on edsk

  :raises ElligatorError: if the key is incompatible with Elligator2
  """
  # Calculate a dirty public key
  s = dirty_scalar(edsk)
  sg = s % 8  # sub group
  # Using dirty generator: s * D - sg * G =
  # Using normal generator: (s - sg) * G + LO[sg] =
  # A dirty point produced: standard edpk + random low-order point
  P = (s - sg) * G + LO[sg]
  if not is_hashable(P.mont): raise ElligatorError("The key cannot be Elligator hashed")
  # Take two pseudorandom bits (custom prefix needed to keep s and signatures secure)
  # sha512(...)[31] & 0xC0 and placing at the same location on the final hidden byte.
  tweak = sha(b"DirtyElligator2:" + edsk) & 0b11 << 254

  # Elligator 2 hash
  #
  # Note: the random hashes lack one bit of entropy because only half of the possible
  # points are created (because the high bit of the scalar is forced on) but for a given
  # point it is not possible to test whether it could or could not be created. Adding a
  # random sign bit instead would add to entropy but then the Ed25519 sign would be lost.
  elligator = fast_curve_to_hash(P.mont, P.is_negative).val
  assert elligator & tweak == 0, "The elligator hash and the tweak should not overlap"
  return tobytes(elligator ^ tweak)

def egreveal(hidden: str) -> EdPoint:
  """Convert the hidden string back to (a dirty) public key"""
  elligator = toint(hidden) & (1 << 254) - 1
  u, v = fast_hash_to_curve(fe(elligator))
  P = EdPoint.from_mont(u, v.is_negative)
  return P

## Low level API follows

# Arbitrary non square, typically chosen to minimise computation.
# 2 and sqrt(-1) both work fairly well, but 2 seems to be more popular.
# We stick to 2 for compatibility.
non_square = fe(2)

# From the paper:
# w = -A / (fe(1) + non_square * r^2)
# e = chi(w^3 + A*w^2 + w)
# u = e*w - (fe(1)-e)*(A//2)
# v = -e * sqrt(u^3 + A*u^2 + u)
ufactor = -non_square * sqrtm1
vfactor = ufactor.sqrt


def fast_hash_to_curve(r: fe) -> Tuple[fe, fe]:
  """Convert a 254-bit hash into a pair of curve coordinates"""
  t1 = r**2 * non_square  # r1
  u = t1 + one  # r2
  t2 = u**2
  t3 = (A**2 * t1 - t2) * A  # numerator
  t1 = t2 * u  # denominator
  t1 = (t3 * t1).invsqrt
  u = r**2 * ufactor
  v = r * vfactor
  if t1.is_square:
    u, v = one, one
  v *= t3 * t1
  u *= -A * t3 * t2 * t1**2
  if t1.is_square != v.is_negative:  # XOR
    v = -v
  return u, v


# From the paper:
# Let sq = -non_square * u * (u+A)
# if sq is not a square, or u = -A, there is no mapping
# Assuming there is a mapping:
#   if v is positive: r = sqrt(-(u+A) / u)
#   if v is negative: r = sqrt(-u / (u+A))
#
# We compute isr = invsqrt(-non_square * u * (u+A))
# if it wasn't a non-zero square, abort.
# else, isr = sqrt(-1 / (non_square * u * (u+A))
#
# This causes us to abort if u is zero, even though we shouldn't. This
# never happens in practice, because (i) a random point in the curve has
# a negligible chance of being zero, and (ii) scalar multiplication with
# a trimmed scalar *never* yields zero.
def fast_curve_to_hash(u: fe, v_is_negative: bool) -> fe:
  """Convert a curve point into a pseudorandom 254 bit value"""
  t = u + A
  r = -non_square * u * t
  isr = r.invsqrt
  if not isr.is_square:
    raise ValueError("The point cannot be mapped.")
  if v_is_negative: u = t
  r = u * isr
  r = abs(r)
  return r


# Unlike the paper, curve coordinates are called (u, v) to follow
# established conventions. Thus, "v" in the paper is called "w" here.
def hash_to_curve(r: fe) -> Tuple[fe, fe]:
  """Reference implementation of S to point"""
  w = -A / (one + non_square * r**2)
  e = (w**3 + A * w**2 + w).chi
  u = e*w - (one - e) * (A//2)
  v = -e * (u**3 + A * u**2 + u).sqrt
  return u, v


# Computes the representative of a point, straight from the paper.
def curve_to_hash(u: fe, v_is_negative: bool) -> fe:
  """Reference implementation of point to S"""
  if not is_hashable(u):
    raise ValueError('cannot curve to hash')
  sq1 = (-u / (non_square * (u+A))).sqrt
  sq2 = (-(u + A) / (non_square * u)).sqrt
  return sq2 if v_is_negative else sq1


def is_hashable(u: fe) -> bool:
  """Test if a point is hashable."""  # Straight from the paper.
  return u != -A and (-non_square * u * (u + A)).is_square
