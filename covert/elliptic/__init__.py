# A plain Python submodule for Ed25519/Curve25519 math and Elligator 2

# Based on code by Loup Vaillant and Andrew Moon (public domain, no warranties)
# https://github.com/LoupVaillant/Monocypher/blob/master/tests/gen/elligator.py

# Heavily changed and extended by Covert, based on Ed25519 RFC and other sources.
# https://datatracker.ietf.org/doc/html/rfc8032

# Not constant time, not zeroing buffers after use, so the Monocypher C library
# should be preferred where needed, in particular with the many things that
# libsodium does not support. This code does not use low order safety mechanisms
# that sodium implements preventing the "dirty points" needed for Elligator.

# Public symbols are imported here. These are very low level primitives.
# Lower case constants are scalars (int or fe), upper case are EdPoints.

from . import mont
from .ed import LO, ZERO, D, EdPoint, G, L, dirty_scalar, secret_scalar
from .eddsa import ed_sign, ed_verify
from .elligator import ElligatorError, egcreate, eghide, egreveal
from .scalar import fe, minus1, one, p, q, sqrtm1, zero
from .util import clamp, tobytes, toint, tointsign
from .xeddsa import xed_sign, xed_verify
