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
  a.file_index(["tests/data/foo.txt"])
  block = Block()
  a.encode(block)
  written = bytes(block.data[:block.pos])
  # {f: [[4, "foo.txt", {}]]} + b'test'
  assert written == b"\x81\xA1f\x91\x93\x04\xA7foo.txt\x80test"
  assert a.stage is Stage.END


def test_encode_files():
  a = Archive()
  a.file_index(2 * ["tests/data/foo.txt"])
  assert a.padding == 0
  block = Block()
  a.encode(block)
  written = bytes(block.data[:block.pos])
  # {f: [[4, "foo.txt", {}], [4, "foo.txt", {}]]} + b'testtest'
  expected = b"\x81\xA1f\x92\x93\x04\xA7foo.txt\x80\x93\x04\xA7foo.txt\x80testtest"
  assert written == expected
  assert a.stage is Stage.END


@pytest.mark.parametrize(
  "expected_out,archive", [
  ([dict(f=[[0, None, {}]]), True, False], b'\x00'),
  ([dict(f=[[4, None, {}]]), True, b"test", False], b'\x04test'),
  ]
)
def test_decode_message(expected_out, archive):
  a = Archive()
  blocks = [archive]
  out = [o for o in a.decode(blocks)]
  assert out == expected_out
  assert a.stage is Stage.END
