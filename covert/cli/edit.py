import sys
from io import BytesIO

from covert import passphrase, util
from covert.archive import Archive, FileRecord
from covert.blockstream import decrypt_file, encrypt_file
from covert.cli import tty


def main_edit(args):
  if len(args.files) != 1:
    raise ValueError("Edit mode requires an encrypted archive filename (or '-' to use stdio).")
  fname = args.files[0]
  # Read all of input file (or stdin) to RAM
  if fname is True:
    data = sys.stdin.buffer.read()
  else:
    with open(fname, "rb") as f:
      data = f.read()
  try:
    infile = BytesIO(util.armor_decode(data.decode()))
    args.armor = True
  except Exception:
    infile = BytesIO(data)
  # Decrypt everything to RAM
  pwhash = passphrase.pwhash(passphrase.ask("Passphrase")[0])
  a = Archive()
  for data in a.decode(decrypt_file([pwhash], infile, a)):
    if isinstance(data, dict): pass
    elif isinstance(data, bool):
      if data: a.curfile.data = bytearray()
    else: a.curfile.data += data
  # Edit the message (should be the first file)
  if a.flist and a.flist[0].name is None:
    a.flist[0].data = util.encode(tty.editor(a.flist[0].data.decode()))
    a.flist[0].size = len(a.flist[0].data)
  else:
    data = util.encode(tty.editor())
    a.flist.insert(0, FileRecord([len(data), None, {}]))
    a.flist[0].data = data
  # Reset archive for re-use in encryption
  a.reset()
  a.fds = [BytesIO(f.data) for f in a.flist]
  a.random_padding()
  # Encrypt in RAM...
  out = bytearray()
  for block in encrypt_file((False, [pwhash], [], []), a.encode, a):
    out += block
  # Preserve armoring if the input was armored
  if args.armor:
    out = f"{util.armor_encode(out)}\n".encode()
  # Finally write output / replace the file
  if fname is True:
    sys.stdout.buffer.write(out)
  else:
    with open(fname, "wb") as f:
      f.write(out)
