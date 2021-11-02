from io import BytesIO
from math import exp

import pytest

from covert.archive import Archive, Stage
from covert.blockstream import Block


def test_encode_empty():
  a = Archive()
  a.file_index([])
  block = Block()
  a.encode(block)
  expected = b'\x80'  # Empty dict
  assert block.data[:block.pos] == expected
  assert a.stage is Stage.END


@pytest.mark.parametrize("text,expected", [
  (b'', b'\x00'),
  (b'test', b'\x04test'),
])
def test_encode_message(text, expected):
  a = Archive()
  a.file_index([BytesIO(text)])
  block = Block()
  a.encode(block)
  written = bytes(block.data[:block.pos])
  assert written == expected
  assert a.stage is Stage.END


def test_encode_file():
  a = Archive()
  a.file_index(["data/foo.txt"])
  block = Block()
  a.encode(block)
  written = bytes(block.data[:block.pos])
  # dict(f=[dict(n="foo.txt", s=4)]) + b'test'
  assert written == b"\x81\xA1f\x91\x82\xA1n\xA7foo.txt\xA1s\x04test"
  assert a.stage is Stage.END


def test_encode_files():
  a = Archive()
  a.file_index(2 * ["data/foo.txt"])
  assert a.padding == 0
  block = Block()
  a.encode(block)
  written = bytes(block.data[:block.pos])
  # dict(f=[dict(n="foo.txt", s=4), dict(n="foo.txt", s=4)]) + b'testtest'
  expected = b"\x81\xA1f\x92\x82\xA1n\xA7foo.txt\xA1s\x04\x82\xA1n\xA7foo.txt\xA1s\x04testtest"
  assert written == expected
  assert a.stage is Stage.END


@pytest.mark.parametrize(
  "expected_out,archive", [
  ([dict(f=[dict(s=0)]), True, False], b'\x00'),
  ([dict(f=[dict(s=4)]), True, b"test", False], b'\x04test'),
  ]
)
def test_decode_message(expected_out, archive):
  a = Archive()
  blocks = [archive]
  out = [o for o in a.decode(blocks)]
  assert out == expected_out
  assert a.stage is Stage.END
