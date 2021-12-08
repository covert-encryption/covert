import pytest
import sys

def test_argparser(capsys):
  from covert.__main__ import argparse  # Import only *after* capsys wraps sys.stdout/stderr

  # Correct but complex arguments
  sys.argv = "covert enc --recipient recipient1 -r recipient2 -Arrp recipient3 recipient4".split()
  a = argparse()
  assert a.recipients == ['recipient1', 'recipient2', 'recipient3', 'recipient4']
  assert a.paste is True
  assert a.askpass == 1
  # Should produce no output
  cap = capsys.readouterr()
  assert not cap.out
  assert not cap.err

  # Giving mode within combined arguments
  sys.argv = "covert -eArrp recipient1 recipient2".split()
  a = argparse()
  assert a.recipients == ['recipient1', 'recipient2']
  assert a.askpass == 1
  assert a.paste is True
  cap = capsys.readouterr()
  assert not cap.out

  # Missing argument parameter
  sys.argv = "covert enc -Arrp recipient1".split()
  with pytest.raises(SystemExit):
    argparse()
  cap = capsys.readouterr()
  assert not cap.out
  assert "Argument parameter missing: covert enc -Arrp …" in cap.err

  # For combined mode
  sys.argv = "covert -eArrp recipient1".split()
  with pytest.raises(SystemExit):
    argparse()
  cap = capsys.readouterr()
  assert not cap.out
  assert "Argument parameter missing: covert enc -Arrp …" in cap.err


def test_end_to_end(capsys, tmp_path):
  from covert.__main__ import main
  import sys
  fname = tmp_path / "crypto.covert"

  # Encrypt data/foo.txt into crypto.covert
  sys.argv = "covert enc tests/data -R tests/keys/ssh_ed25519.pub -o".split() + [ str(fname) ]
  ret = main()
  cap = capsys.readouterr()
  assert not ret
  assert not cap.out
  assert "foo" in cap.err

  # Decrypt
  sys.argv = "covert dec -i tests/keys/ssh_ed25519".split() + [ str(fname), "-o", str(tmp_path)]
  ret = main()
  cap = capsys.readouterr()
  assert not ret
  assert not cap.out
  assert "foo.txt" in cap.err

  # Check the file just extracted
  with open(tmp_path / "data" / "foo.txt", "rb") as f:
    data = f.read()
  assert data == b"test"
