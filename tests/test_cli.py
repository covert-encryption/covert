import os
import sys
from io import BytesIO, TextIOWrapper

import pytest

from covert import passphrase, path
from covert.cli.__main__ import main
from covert.cli.args import argparse
from covert.cli.dec import main_dec
from covert.cli.edit import main_edit


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

  # For double-hyphen file separator (to not parse anything after as args)
  sys.argv = "covert enc -- filename --help --notaflag -A".split()
  args = argparse()
  assert args.files == ["filename", "--help", "--notaflag", "-A"]
  assert not args.paste


## End-to-End testing: Running Covert as if it was ran from command line

# A fixture to run covert more easily, checks exitcode and returns its output
@pytest.fixture
def covert(monkeypatch, capsys):
  def run_main(*args, stdin="", exitcode=0):
    if args and args[0] == "covert":
      raise ValueError("Only arguments please, no 'covert' in the beginning")
    sys.argv = [str(arg) for arg in ("covert", *args)]
    monkeypatch.setattr("sys.stdin", TextIOWrapper(BytesIO(stdin.encode())))  # Inject stdin
    monkeypatch.setattr("covert.passphrase.ARGON2_MEMLIMIT", 1 << 20)  # Gotta go faster
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


def test_end_to_end_multiple(covert, tmp_path, mocker):
  # Enable full status messages
  mocker.patch("sys.stderr.isatty", return_value=True)

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
  assert "Signed by Key[827bc3b2:PK]" in cap.err

  # Decrypt with passphrase
  cap = covert('dec', '--password', 'verytestysecret', fname)
  assert not cap.out
  assert "foo.txt" in cap.err
  assert "Signed by Key[827bc3b2:PK]" in cap.err

  # Decrypt with wrong key
  cap = covert('dec', '-i', 'tests/keys/ssh_ed25519', fname, exitcode=10)
  assert not cap.out
  assert "Not authenticated" in cap.err


def test_end_to_end_github(covert, tmp_path, mocker):
  # Enable full status messages
  mocker.patch("sys.stderr.isatty", return_value=True)
  # Fake web requests unless COVERT_TEST_GITHUB=1 is set (don't wanna 'call home' without permission)
  allow_network = os.environ.get("COVERT_TEST_GITHUB") == "1"
  if allow_network:
    m = mocker.spy("covert.pubkey.urlopen")
  else:
    class FakeResponse:
      def __enter__(self): return self
      def __exit__(self, *exc): pass
      def read(self):
        with open("tests/keys/ssh_ed25519.pub", "rb") as f:
          return f.read()
    m = mocker.patch("covert.pubkey.urlopen", return_value=FakeResponse())

  outfname = tmp_path / "crypto.covert"
  cap = covert("enc", "-R", "github:covert-encryption", "--out", outfname, "tests/data/foo.txt")
  assert not cap.out
  assert "4 📄 foo.txt" in cap.err
  assert "covert-encryption@github" in cap.err
  m.assert_any_call("https://github.com/covert-encryption.keys")


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

  # Decrypt crypto.covert to check the file list
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


def test_end_to_end_edit(covert, tmp_path, mocker):
  fname = tmp_path / "crypto.covert"
  mocker.patch("covert.passphrase.ask", return_value=(b"verytestysecret", True))

  # Encrypt data/foo.txt into crypto.covert
  cap = covert("enc", "tests/data", "-o", fname)
  assert not cap.out
  assert "foo" in cap.err

  editor = mocker.patch("covert.cli.tty.editor", return_value="added message")
  cap = covert("edit", fname)
  editor.assert_called_once_with()

  editor = mocker.patch("covert.cli.tty.editor", return_value="edited message")
  cap = covert("edit", fname)
  editor.assert_called_once_with("added message")

  # Decrypt
  cap = covert("dec", fname, "-o", tmp_path)
  assert "edited message" in cap.out
  assert "foo.txt" in cap.err
  # Check the file just extracted
  with open(tmp_path / "data" / "foo.txt", "rb") as f:
    data = f.read()
  assert data == b"test"


def test_end_to_end_edit_armored_stdio(covert, mocker, monkeypatch):
  """echo original message | covert enc | covert edit - | covert dec"""
  # Would ask for passphrase and new message on TTY despite stdin and stdout being piped
  mocker.patch("covert.passphrase.ask", return_value=(b"verytestysecret", True))

  # Encrypt a message
  cap = covert("enc", "-a", stdin="original message")
  assert cap.out and cap.out.isascii()

  # Edit the message stdio
  editor = mocker.patch("covert.cli.tty.editor", return_value="edited message")
  cap = covert("edit", "-", stdin=cap.out)
  assert cap.out and cap.out.isascii()
  assert not cap.err
  editor.assert_called_once_with("original message")

  # Decrypt
  cap = covert("dec", "--password", "verytestysecret", stdin=cap.out)
  assert "edited message" in cap.out


def test_idstore(covert, mocker, tmp_path):
  outfname = tmp_path / "crypto.covert"
  mocker.patch("covert.passphrase.ask", return_value=(b"verytestysecret", True))

  # Enable full status messages
  mocker.patch("sys.stderr.isatty", return_value=True)

  # Test environment should set XDG_DATA_DIR outside of standard location
  assert "/tmp/" in str(path.idfilename)

  # Create ID store
  cap = covert("id", "alice")
  assert "Creating" in cap.err
  assert "Master ID passphrase:" in cap.err
  assert "verytestysecret" in cap.err
  assert "id:alice" in cap.out
  assert "age1" in cap.out

  # Encrypt
  cap = covert("enc", "-I", "alice:testkey", "-R", "tests/keys/ssh_ed25519.pub", "-o", outfname)
  assert "🔗 id:alice:testkey" in cap.err
  assert "🖋️ id:alice" in cap.err

  # Add secret key
  cap = covert("id", "bob", "-i", "tests/keys/ssh_ed25519")
  assert "id:bob" in cap.out

  # Decrypt using idstore
  cap = covert("dec", outfname)
  assert "Unlocked with id:bob" in cap.err
  assert "Signed by id:alice" in cap.err

  # Encrypt with local id as peer
  cap = covert("enc", "-I", "alice:bob", "-o", outfname)
  assert "🔗 id:alice:bob" in cap.err
  assert "🖋️ id:alice" in cap.err

  # Decrypt using idstore
  cap = covert("dec", outfname)
  assert "Unlocked with id:bob" in cap.err
  assert "Signed by id:alice" in cap.err

  # List keys
  cap = covert("id", "--secret")
  assert "id:alice" in cap.out
  assert "id:alice:testkey" in cap.out
  assert "AGE-SECRET-KEY" in cap.out
  assert "id:alice:bob" in cap.out

  # Delete peer
  cap = covert("id", "--delete", "alice:bob")
  assert f"alice:bob" not in cap.out

  # Delete local
  cap = covert("id", "--delete", "alice")
  assert f"alice" not in cap.out

  # Test decryption errors

  mocker.patch("covert.passphrase.ask", return_value=(b"wrong passphrase", True))
  cap = covert("dec", outfname, exitcode=10)
  assert "ID store: Not authenticated" in cap.err

  cap = covert("dec", outfname, "-p", exitcode=10)
  assert "ID store" not in cap.err
  assert "Not authenticated" in cap.err

  mocker.patch("covert.passphrase.ask", return_value=(b"", True))
  cap = covert("dec", outfname, exitcode=10)
  assert "ID store" not in cap.err
  assert "Too short password" in cap.err

  # Shred
  cap = covert("id", "--delete-entire-idstore")
  assert f"{path.idfilename} shredded and deleted" in cap.err


def test_ratchet(covert, mocker, tmp_path):
  outfname = tmp_path / "crypto.covert"
  mocker.patch("covert.passphrase.ask", return_value=(b"verytestysecret", True))

  # Enable full status messages
  mocker.patch("sys.stderr.isatty", return_value=True)

  # Test environment should set XDG_DATA_DIR outside of standard location
  assert "/tmp/" in str(path.idfilename)

  # Create IDs
  cap = covert("id", "alice")
  assert "age1" in cap.out

  cap = covert("id", "bob", "-i", "tests/keys/ageid-age1cghwz85tpv2eutkx8vflzjfa9f96wad6d8an45wcs3phzac2qdxq9dqg5p")
  assert "age1cghwz85tpv2eutkx8vflzjfa9f96wad6d8an45wcs3phzac2qdxq9dqg5p" in cap.out

  # Alice encrypts initial message
  cap = covert("enc", "-I", "alice:bob", "-o", outfname)
  assert "🔗 id:alice:bob" in cap.err
  assert "🖋️ id:alice" in cap.err

  # Bob decrypts
  cap = covert("dec", "-I", "bob:alice", outfname)
  assert "Unlocked with id:bob" in cap.err
  assert "Signed by id:alice" in cap.err

  # Bob replies
  cap = covert("enc", "-I", "bob:alice", "-o", outfname)
  assert "🔗 #1" in cap.err

  # Alice decrypts
  cap = covert("dec", outfname)
  assert "Conversation id:alice:bob" in cap.err

  # Bob sends another (no round-trip, message lost)
  cap = covert("enc", "-I", "bob:alice", "-o", outfname)
  assert "🔗 #2" in cap.err

  # Bob sends another (no round-trip)
  cap = covert("enc", "-I", "bob:alice", "-o", outfname)
  assert "🔗 #3" in cap.err

  # Alice decrypts
  cap = covert("dec", outfname)
  assert "Conversation id:alice:bob" in cap.err

  # Alice replies (first normal ratchet message from her)
  cap = covert("enc", "-I", "alice:bob", "-o", outfname)
  assert "🔗 #2" in cap.err

  # Bob decrypts
  cap = covert("dec", outfname)
  assert "Conversation id:bob:alice" in cap.err

  # Shred
  cap = covert("id", "--delete-entire-idstore")
  assert f"{path.idfilename} shredded and deleted" in cap.err


def test_errors(covert):
  cap = covert()
  assert "Covert" in cap.out
  assert not cap.err

  cap = covert('-eINvalid', '--help')
  assert "Covert" in cap.out
  assert not cap.err

  cap = covert('-eINvalid', exitcode=1)
  assert not cap.out
  assert "Unknown argument: covert enc -INvalid (failing -N -v -l -d)" in cap.err

  cap = covert("-o", exitcode=1)
  assert not cap.out
  assert "Invalid or missing command" in cap.err

  # FIXME: These should probably have status code 1 like the other argument errors do
  # Needs more exception types to implement such distinction.

  cap = covert("enc", "-r", "github:covert-encryption", exitcode=10)
  assert not cap.out
  assert "Unrecognized recipient string. Download a key from Github by -R github:covert-encryption" in cap.err

  cap = covert("enc", "-r", "tests/keys/ssh_ed25519.pub", exitcode=10)
  assert not cap.out
  assert "Unrecognized recipient string. Use a keyfile by -R tests/keys/ssh_ed25519.pub" in cap.err

  cap = covert("enc", "-r", "not-a-file-either", exitcode=10)
  assert not cap.out
  assert "Unrecognized key not-a-file-either" in cap.err

  cap = covert("enc", "--id", "alice:bob", exitcode=10)
  assert not cap.out
  assert "Peer not in ID store. You need to specify a recipient public key on the first use." in cap.err

  cap = covert("id", "alice", "bob", exitcode=10)
  assert not cap.out
  assert "one ID at most should be specified" in cap.err

  cap = covert("id", "alice", "--delete-entire-idstore", exitcode=10)
  assert not cap.out
  assert "No ID should be provided with --delete-entire-idstore" in cap.err

  assert not path.idfilename.exists()
  cap = covert("id", "--delete-entire-idstore")  # Note: exitcode 0
  assert not cap.out
  assert "does not exist" in cap.err

  cap = covert("id", "--delete", exitcode=10)
  assert not cap.out
  assert "Need an ID of form yourname or yourname:peername to delete." in cap.err

  cap = covert("id", "-i", "tests/keys/ssh_ed25519.pub", exitcode=10)
  assert not cap.out
  assert "Need an ID to assign a secret key." in cap.err

  cap = covert("id", "alice", "-R", "tests/keys/ssh_ed25519.pub", exitcode=10)
  assert not cap.out
  assert "Need an ID of form yourname:peername to assign a public key" in cap.err

  cap = covert("id", "alice:bob", "-R", "tests/keys/ssh_ed25519.pub", "-r", "age1fakekey", exitcode=10)
  assert not cap.out
  assert "Only one public key may be specified" in cap.err

  cap = covert("id", "alice", "-i", "tests/keys/ssh_ed25519", "-i", "tests/keys/minisign.key", exitcode=10)
  assert not cap.out
  assert "Only one secret key may be specified for ID store" in cap.err

  cap = covert("id", exitcode=10)
  assert not cap.out
  assert "To create a new ID store, specify an ID to create" in cap.err

  cap = covert("id", "alice:bob", exitcode=10)
  assert not cap.out
  assert "No public key provided for new peer id:alice:bob." in cap.err


def test_miscellaneous(covert, tmp_path, capsys, mocker):
  """Testing remaining spots to gain full coverage."""
  fname = tmp_path / "test.dat"
  outfname = tmp_path / "crypto.covert"

  # Write 10 MiB on test.dat
  with open(f"{fname}", "wb") as f:
    f.seek(10485760)
    f.write(b"\0")

  cap = covert("-eaR", "tests/keys/ssh_ed25519.pub", fname, "-o", outfname, "--debug")
  assert not cap.out
  assert "10,485,761 📄 test.dat" in cap.err

  cap = covert("-v")
  assert "A file and message encryptor" not in cap.out
  assert "Covert " in cap.out
  assert not cap.err

  cap = covert("-e", 1, "-z", exitcode=1)
  assert not cap.out
  assert "Unknown argument" in cap.err

  with pytest.raises(ValueError):
    cap = covert("-e", "-o", "test.dat", "-o", "test2.dat", exitcode=1)
    assert not cap.out
    assert "Only one output file may be specified" in cap.err

  with pytest.raises(ValueError):
    cap = covert("-eaR", "tests/keys/ssh_ed25519.pub", fname, "-o", fname, exitcode=1)
    assert not cap.out
    assert "In-place operation is not supported" in cap.err

  sys.argv = "covert enc --passphrase".split()
  a = argparse()
  assert a.askpass == 1
  cap = capsys.readouterr()
  assert not cap.out
  assert not cap.err

  mocker.patch("covert.passphrase.ask", side_effect=KeyboardInterrupt("Testing interrupt"))
  cap = covert("enc", exitcode=2)
  assert not cap.out
  assert "Interrupted." in cap.err

  # A typical case of Broken Pipe: the program being piped to exits and then stdout writes fail
  mocker.patch("sys.stdout.buffer.write", side_effect=BrokenPipeError())
  cap = covert("-eR", "tests/keys/ssh_ed25519.pub", fname, exitcode=3)
  assert not cap.out
  assert "I/O error (broken pipe)" in cap.err


def test_files_count():
  sys.argv = "covert dec testfile1.txt testfile2.txt".split()
  args = argparse()
  with pytest.raises(ValueError) as exc:
    main_dec(args)
  assert "Only one input file is allowed when decrypting" in str(exc.value)

  sys.argv = "covert edit".split()
  args = argparse()
  with pytest.raises(ValueError) as exc:
    main_edit(args)
  assert "Edit mode requires an encrypted archive filename" in str(exc.value)
