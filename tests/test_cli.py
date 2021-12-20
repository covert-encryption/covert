import pytest
import sys
from covert.__main__ import argparse, main

def test_argparser(capsys):
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


## End-to-End testing: Running Covert as if it was ran from command line

# A fixture to run covert more easily, checks exitcode and returns its output
@pytest.fixture
def covert(capsys):
  def run_main(*args, exitcode=0):
    if args and args[0] == "covert":
      raise ValueError("Only arguments please, no 'covert' in the beginning")
    sys.argv = [str(arg) for arg in ("covert", *args)]
    with pytest.raises(SystemExit) as exc:
      main()
    assert exc.value.code == exitcode, f"Was expecting {exitcode=} but Covert did sys.exit({exc.value.code})"
    return capsys.readouterr()
  return run_main


def test_end_to_end(covert, tmp_path):
  fname = tmp_path / "crypto.covert"

  # Encrypt data/foo.txt into crypto.covert
  cap = covert("enc", "tests/data", "-R", "tests/keys/ssh_ed25519.pub", "-o", fname)
  assert not cap.out
  assert "foo" in cap.err

  # Decrypt
  cap = covert("dec", "-i", "tests/keys/ssh_ed25519", fname, "-o", tmp_path)
  assert not cap.out
  assert "foo.txt" in cap.err

  # Check the file just extracted
  with open(tmp_path / "data" / "foo.txt", "rb") as f:
    data = f.read()
  assert data == b"test"


def test_end_to_end_multiple(covert, tmp_path):
  fname = tmp_path / "crypto.covert"

  # Encrypt foo.txt into crypto.covert, with signature
  cap = covert(
    'enc',
    'tests/data/foo.txt',
    '-i', 'tests/keys/ssh_ed25519',
    '--password', 'verytestysecret',
    '-r', 'age1cghwz85tpv2eutkx8vflzjfa9f96wad6d8an45wcs3phzac2qdxq9dqg5p',
    '-o', fname,
  )
  assert not cap.out
  assert "foo" in cap.err

  # Decrypt with key
  cap = covert(
    'dec',
    '-i', 'tests/keys/ageid-age1cghwz85tpv2eutkx8vflzjfa9f96wad6d8an45wcs3phzac2qdxq9dqg5p',
    fname,
  )
  assert not cap.out
  assert "foo.txt" in cap.err
  assert "Key[827bc3b2:EdPK] Signature verified" in cap.err

  # Decrypt with passphrase
  cap = covert('dec', '--password', 'verytestysecret', fname)
  assert not cap.out
  assert "foo.txt" in cap.err
  assert "Key[827bc3b2:EdPK] Signature verified" in cap.err


def test_end_to_end_shortargs_armored(covert, tmp_path):
  fname = tmp_path / "crypto.covert"

  # Encrypt foo.txt into crypto.covert
  cap = covert("-eRao", "tests/keys/ssh_ed25519.pub", fname, 'tests/data/foo.txt')
  assert not cap.out
  assert "foo" in cap.err

  # Decrypt with key
  cap = covert("-di", "tests/keys/ssh_ed25519", fname)
  assert not cap.out
  assert "foo.txt" in cap.err


def test_end_to_end_armormaxsize(covert, tmp_path):
  fname = tmp_path / "test.dat"
  outfname = tmp_path / "crypto.covert"

  # Write 31 MiB on test.dat
  with open(f"{fname}", "wb") as f:
    f.seek(32505855)
    f.write(b"\0")

  # Encrypt test.dat with armor and no padding
  cap = covert("enc", fname, "-R", "tests/keys/ssh_ed25519.pub", "--pad", 0, "-ao", outfname)
  assert not cap.out
  assert "32,505,856 📄 test.dat" in cap.err

  # Decrypt crypto.covert with passphrase
  cap = covert("-di", "tests/keys/ssh_ed25519", outfname)
  assert not cap.out
  assert "32,505,856 📄 test.dat" in cap.err


def test_end_to_end_large_file(covert, tmp_path):
  fname = tmp_path / "test.dat"
  outfname = tmp_path / "crypto.covert"

  # Write file with size too large for --armor
  with open(f"{fname}", "wb") as f:
    f.seek(42505855)
    f.write(b"\0")

  # Try encrypting without -o
  cap = covert("-eaR", "tests/keys/ssh_ed25519.pub", fname, exitcode=10)
  assert not cap.out
  assert "How about -o FILE to write a file?" in cap.err

  # Try encrypting with -o
  cap = covert("-eaRo", "tests/keys/ssh_ed25519.pub", outfname, fname, exitcode=10)
  assert not cap.out
  assert "The data is too large for --armor." in cap.err


def test_errors(covert):
  cap = covert()
  assert "Usage:" in cap.out
  assert not cap.err

  cap = covert('-eINvalid', '--help')
  assert "Usage:" in cap.out
  assert not cap.err

  cap = covert('-eINvalid', exitcode=1)
  assert not cap.out
  assert "not an argument: covert enc -INvalid" in cap.err

  cap = covert("-o", exitcode=1)
  assert not cap.out
  assert "Invalid or missing command" in cap.err
