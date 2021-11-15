from secrets import token_bytes

import pytest

from covert.util import armor_decode, armor_encode


def test_armor_valid():
  data = token_bytes(10000)
  for i in [10000, 9999, 9998, 9000, 5000] + list(range(100)):
    d = data[i:]
    text = armor_encode(d)
    binary = armor_decode(b'\n\n     ```\n' + text.replace(b'\n', b'   \r\n\t  ') + b'```\n\n')
    assert binary == d


def test_armor_decode_invalid():
  valid_line = 76*b'A' + b'\n'
  valid_out = bytes(57)
  assert armor_decode(valid_line) == valid_out

  with pytest.raises(ValueError) as exc:
    armor_decode(b'\x80')
  assert "ASCII" in str(exc.value)

  with pytest.raises(ValueError) as exc:
    armor_decode(b'!')
  assert "unrecognized data on line 1" in str(exc.value)

  # Minimum length for all but the last line is 76
  with pytest.raises(ValueError) as exc:
    armor_decode(valid_line[4:] + valid_line)
  assert "length 72 of line 1" in str(exc.value)

  # Lines must have equal length
  with pytest.raises(ValueError) as exc:
    armor_decode(b'AAAA' + valid_line + valid_line + valid_line)
  assert "length 76 of line 2" in str(exc.value)

  # Lines must be divisible by four
  with pytest.raises(ValueError) as exc:
    armor_decode(b'A' + valid_line + valid_line)
  assert "length 77 of line 1" in str(exc.value)
