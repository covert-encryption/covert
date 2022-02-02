from io import BytesIO
from secrets import token_bytes
from time import sleep

import pytest

from covert.archive import Archive
from covert.blockstream import BS, decrypt_file, encrypt_file

AUTH = False, [b'justfakepasshash'], [], []
AUTH_DEC = [b'justfakepasshash']


@pytest.mark.parametrize(
  "datasizes, ciphersizes", [
  ([1], [12, 20]),
  ([10, BS], [12, 29, BS + 19]),
  ([None, 512, BS, 1], [12, 1024 - 12, 512 + 19, BS + 19, 20]),
  ]
)
def test_consume_varying_block_sizes(datasizes, ciphersizes):
  """Tests the ability of the encrypter to format correctly sized blocks."""

  def blockinput(block):
    try:
      n = next(num) or block.spaceleft
      data = block.consume(bytes(n))
      assert not data
    except StopIteration:
      pass

  a = Archive()
  e = encrypt_file(AUTH, blockinput, a)
  num = iter(datasizes)
  for cipherblock, expected_length in zip(e, ciphersizes):
    assert len(cipherblock) == expected_length
  with pytest.raises(StopIteration):
    next(e)


@pytest.mark.skip(reason="Implementation of minimal delays slowed down execution too much.")
@pytest.mark.parametrize(
  "values, expected_seq", [
  ([(20, False), (21, False), (22, False)], [12, -20, -21, 20, -22, 21, 22]),
  ([(20, 21), (21, 22), (22, False)], [12, -20, 20, -21, 21, -22, 22]),
  ]
)
def test_latencies(values, expected_seq):
  """Tests the ability to forward blocks as soon as the nextlen is known."""

  def blockinput(block):
    try:
      # Wait a little to allow the other threads be faster
      sleep(0.1)
      v = next(values)
      block.pos = v[0] - 19
      if v[1]:
        block.nextlen = v[1] - 19
      seq.append(-v[0])
    except StopIteration:
      pass

  values = iter(values)
  seq = []
  e = encrypt_file(AUTH, blockinput)
  for cipherblock in e:
    seq.append(len(cipherblock))
  assert seq == expected_seq
  with pytest.raises(StopIteration):
    next(e)


@pytest.mark.parametrize("size", [1, 1100, 5000, 20 << 20])
def test_encrypt_decrypt(size):
  """Verify that the blockstream level encrypt-decrypt cycle works as intended."""

  def blockinput(block):
    block.pos = inf.readinto(block.data)

  plaintext = token_bytes(size)
  inf = BytesIO(plaintext)
  a = Archive()
  ciphertext = b"".join(encrypt_file(AUTH, blockinput, a))

  lenplain = len(plaintext)
  lencipher = len(ciphertext)
  calculatedcipher = 12 + 19 + lenplain + (lenplain - (1024-12-19) + BS - 1) // BS * 19
  assert lencipher == calculatedcipher
  f = BytesIO(ciphertext)
  a = Archive()
  plainout = b"".join(decrypt_file(AUTH_DEC, f, a))
  assert plainout == plaintext


def test_data_corruption():
  def blockinput(block):
    block.pos = inf.readinto(block.data)

  plaintext = token_bytes(1100)
  inf = BytesIO(plaintext)
  a = Archive()
  ciphertext = bytearray().join(encrypt_file(AUTH, blockinput, a))
  ciphertext[-50] ^= 1  # Flip a bit
  f = BytesIO(ciphertext)
  a = Archive()
  with pytest.raises(ValueError) as e:
    plainout = b"".join(decrypt_file(AUTH_DEC, f, a))
  assert str(e.value) == "Data corruption: Failed to decrypt ciphertext block of 126 bytes"
