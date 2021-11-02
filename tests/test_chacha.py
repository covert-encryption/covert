from secrets import token_bytes

import pytest
from nacl.exceptions import CryptoError

from covert import chacha


def test_inplace():
  """Encrypt and decrypt various block sizes so that the source and the destination are the same buffer."""
  nonce = token_bytes(12)
  key = token_bytes(32)
  for N in range(512):
    buf = memoryview(bytearray(token_bytes(N + 16)))
    orig = bytes(buf)
    ret = chacha.encrypt_into(buf, buf[:N], None, nonce, key)
    assert ret == 0
    tag = buf[N:]
    ret = chacha.decrypt_into(buf[:N], buf, None, nonce, key)
    assert ret == 0
    assert buf[:N] == orig[:N]
    assert buf[N:] == tag


def test_simple():
  nonce = token_bytes(12)
  key = token_bytes(32)
  ct = chacha.encrypt(b'testing', None, nonce, key)
  pt = chacha.decrypt(ct, None, nonce, key)
  assert pt == b'testing'

  with pytest.raises(CryptoError):
    chacha.decrypt(bytes(64), b'foo', nonce, key)
