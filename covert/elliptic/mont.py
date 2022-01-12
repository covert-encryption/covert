from . import ed
from .scalar import fe, minus1, one, zero

# Curve25519 constants on Montgomery curve: B v2 = u3 + A u2 + u
A = fe(486662)  # = fe(2) * (ed.a + ed.d) / (ed.a - ed.d)
B = one

# The point at infinity is represented by u coordinate value minus1 because
#  - No established standard in other libraries (most use zero which is a different low order point)
#  - This is the only number for which there is no birational conversion to Ed25519 (division by zero)
#  - This is not a valid point on the curve (v2 = 486660 which is not square)
#  - The Montgomery ladder misbehaves with this value

def v(u: fe) -> fe:
  """Calculate the v coordinate for a point, checking point validity as well."""
  v2 = u**3 + A * u.sq + u
  if v2.is_square: return v2.sqrt
  if u == minus1:
    raise ValueError("Curve25519 point at infinity does not have coordinates")
  raise ValueError(f"Curve25519 {u=} is not a valid point")


def scalarmult(s: int, u: fe):
  """Multiply point u coordinate by scalar s in Curve25519"""
  if hasattr(u, "mont"): u = u.mont  # type: ignore
  s %= 8 * ed.q
  # Special care of two low order points that the algorithm mishandles
  if u == minus1: return minus1  # Point at infinity
  if u == zero: return zero if s & 1 else minus1  # Low order point with order 2
  # Montgomery ladder
  # In projective coordinates, to avoid divisions: u = X / Z
  x2, z2 = one, zero  # "zero" point
  x3, z3 = u, one     # "one" point
  swap = False
  for n in reversed(range(s.bit_length())):
    bit = bool(s & 1 << n)
    swap ^= bit
    if swap:
      x2, x3 = x3, x2
      z2, z3 = z3, z2
    swap = bit  # anticipates one last swap after the loop

    # Montgomery ladder step: replaces (P2, P3) by (P2*2, P2+P3) with differential addition
    a, b = x2 + z2, x2 - z2
    aa, bb = a.sq, b.sq
    da = a * (x3 - z3)
    db = b * (x3 + z3)
    e = aa - bb
    # Output
    x3, z3 = (da + db).sq, (da - db).sq * u
    x2, z2 = aa * bb, (bb + fe(121666) * e) * e

  # last swap is necessary to compensate for the xor trick
  if swap:
    x2, x3 = x3, x2
    z2, z3 = z3, z2

  # normalises the coordinates: u == X / Z
  return x2 / z2 if z2 != zero else zero if x2 == zero else minus1
