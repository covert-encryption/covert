import mmap
import os
import sys
import itertools
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from io import BytesIO
from pathlib import Path
from time import perf_counter

import pyperclip
from tqdm import tqdm

from covert import lazyexec, passphrase, pubkey, tty, util
from covert.archive import Archive
from covert.blockstream import decrypt_file, encrypt_file

ARMOR_MAX_SIZE = 32 << 20  # If output is a file (limit our memory usage)
TTY_MAX_SIZE = 100 << 10  # If output is a tty (limit too lengthy spam)


def run_decryption(infile, args, auth):
  a = Archive()
  progress = None
  outdir = None
  f = None
  messages = []
  for data in a.decode(decrypt_file(auth, infile, a)):
    if isinstance(data, dict):
      # Header parsed, check the file list
      for i, infile in enumerate(a.flist):
        if infile.name is None:
          if infile.size is None or infile.size > TTY_MAX_SIZE:
            infile.name = f'noname.{i+1:03}'
            infile.renamed = True
        elif infile.name[0] == '.':
          infile.name = f"noname.{i+1:03}{infile['n']}"
          infile.renamed = True
      progress = tqdm(
        ncols=78,
        unit='B',
        unit_scale=True,
        total=a.total_size,
        bar_format="{l_bar}         {bar}{r_bar}",
        disable=a.total_size < 1 << 20
      )
    elif isinstance(data, bool):
      # Nextfile
      prev = a.prevfile
      if f:
        if isinstance(f, BytesIO):
          f.seek(0)
          data = f.read()
          try:
            messages.append(data.decode())
          except UnicodeDecodeError:
            pidx = a.flist.index(prev)
            prev.name = f"noname.{pidx + 1:03}"
            prev.renamed = True
            with get_writable_file(prev.name) as f2:
              f2.write(data)
        f.close()
        f = None
      if prev and prev.name is not None:
        r = '<renamed>' if prev.renamed else ''
        progress.write(f'{prev.size:15,d} 📄 {prev.name:60}{r}', file=sys.stderr)
      if a.curfile:
        n = a.curfile.name or ''
        if not n and a.curfile.size is not None and a.curfile.size < TTY_MAX_SIZE:
          f = BytesIO()
        elif args.outfile:
          if not outdir:
            outdir = Path(args.outfile).resolve()
            outdir.mkdir(parents=True, exist_ok=True)
            progress.write(f" ▶️ \x1B[1;34m  Extracting to \x1B[1;37m{outdir}\x1B[0m", file=sys.stderr)
          name = outdir.joinpath(n)
          if not name.resolve().is_relative_to(outdir) or name.is_reserved():
            progress.close()
            raise ValueError(f'Invalid filename {n!r}')
          name.parent.mkdir(parents=True, exist_ok=True)
          f = open(name, 'wb')
        elif outdir is None:
          outdir = False
          progress.write(
            " ▶️ \x1B[1;34m  The archive contains files. To extract, use \x1B[1;37m-o PATH\x1B[0m", file=sys.stderr
          )

      # Next file
      if progress:
        if a.fidx is not None:
          progress.set_description(f'{a.fidx + 1:03}/{len(a.flist):03}')
        else:
          progress.set_description('')
    else:
      if f:
        f.write(data)
      if progress:
        progress.update(len(data))
  if progress:
    progress.close()
  # Print any messages
  pretty = sys.stdout.isatty()
  for i, m in enumerate(messages):
    if pretty:
      sys.stderr.write("\x1B[1m 💬\n\x1B[1;34m")
      sys.stderr.flush()
      # Replace dangerous characters
      m = ''.join(c if c.isprintable() or c in ' \t\n' else f'\x1B[31m{repr(c)[1:-1]}\x1B[1;34m' for c in m)
    try:
      print(m)
    finally:
      if pretty:
        sys.stderr.write(f"\x1B[0m")
        sys.stderr.flush()
  # Print signatures
  sys.stderr.write(f' 🔷 File hash: {a.filehash[:12].hex()}\n')
  for valid, key, text in a.signatures:
    if valid:
      sys.stderr.write(f" ✅ {key} {text}\n")
    else:
      sys.stderr.write(f"\x1B[1;31m ❌ {key} {text}\x1B[0m\n")


def main_enc(args):
  padding = .01 * float(args.padding) if args.padding is not None else .05
  if not 0 <= padding <= 3.0:
    raise ValueError('Invalid padding specified. The valid range is 0 to 300 %.')
  if not (args.askpass or args.passwords or args.recipients or args.recipfiles or args.wideopen):
    args.askpass = 1
  numpasswd = args.askpass + len(args.passwords)
  passwords, vispw = [], []
  for i in range(args.askpass):
    num = f" {i+1}/{numpasswd}" if numpasswd > 1 else ""
    pw, visible = passphrase.ask(f"New passphrase{num}", create=True)
    passwords.append(pw)
    if visible:
      vispw.append(pw.decode())
    del pw
  passwords += map(util.encode, args.passwords)
  # Use threaded password hashing for parallel and background operation
  with ThreadPoolExecutor(max_workers=4) as executor:
    pwhasher = executor.map(passphrase.pwhash, set(passwords))
    # Convert recipient definitions into keys
    recipients = []
    for keystr in args.recipients:
      try:
        recipients.append(pubkey.decode_pk(keystr))
      except ValueError as e:
        if os.path.isfile(keystr):
          raise ValueError(f"Unrecognized recipient string. Use a keyfile by -R {keystr}")
        raise
    for fn in args.recipfiles:
      recipients += pubkey.read_pk_file(fn)
    # Unique recipient keys sorted by keystr
    l = len(recipients)
    recipients = list(sorted(set(recipients), key=str))
    if len(recipients) < l:
      sys.stderr.write(' ⚠️ Duplicate recipient keys dropped.\n')
    # Signatures
    signatures = {key for keystr in args.identities for key in pubkey.read_sk_any(keystr) if key.edsk}
    signatures = list(sorted(signatures, key=str))
    # Input files
    if not args.files or True in args.files:
      if sys.stdin.isatty():
        data = tty.editor()
        # Prune surrounding whitespace
        data = '\n'.join([l.rstrip() for l in data.split('\n')]).strip('\n')
        stin = util.encode(data)
      else:
        stin = sys.stdin.buffer
      args.files = [stin] + [f for f in args.files if f != True]
    # Collect the password hashing results
    if passwords and sys.stderr.isatty():
      sys.stderr.write("Password hashing... ")
      sys.stderr.flush()
    pwhashes = set(pwhasher)
    if passwords and sys.stderr.isatty():
      sys.stderr.write("\r\x1B[0K")
      sys.stderr.flush()
    del passwords
  a = Archive()
  a.file_index(args.files)
  if signatures:
    a.index['s'] = [s.edpk for s in signatures]
  # Output files
  realoutf = open(args.outfile, "wb") if args.outfile else sys.stdout.buffer
  if args.armor or not args.outfile and sys.stdout.isatty():
    if a.total_size > (ARMOR_MAX_SIZE if args.outfile else TTY_MAX_SIZE):
      if not args.outfile:
        raise ValueError("Too much data for console. How about -o FILE to write a file?")
      raise ValueError("The data is too large for --armor.")
    outf = BytesIO()
  else:
    outf = realoutf
  # Print files during encoding and update padding size at the end
  def nextfile_callback(prev, cur):
    if prev:
      s, n = prev.size, prev.name
      progress.write(f'{s:15,d} 📄 {n:60}' if n else f'{s:15,d} 💬 <message>', file=sys.stderr)
    if not cur:
      a.random_padding(padding)
      progress.write(f'\x1B[1;30m{a.padding:15,d} ⬛ <padding>\x1B[0m', file=sys.stderr)

  a.nextfilecb = nextfile_callback
  # Main processing
  with outf:
    with tqdm(
      total=a.total_size, delay=1.0, ncols=78, unit='B', unit_scale=True, bar_format="{l_bar}         {bar}{r_bar}"
    ) as progress:
      for block in encrypt_file((args.wideopen, pwhashes, recipients, signatures), a.encode, a):
        progress.update(len(block))
        outf.write(block)
    # Pretty output printout
    if sys.stderr.isatty():
      # Print a list of files
      lock = " 🔓 wide-open" if args.wideopen else " 🔒 covert"
      methods = "  ".join(
        [f"🔗 {r}" for r in recipients] + [f"🔑 {a}" for a in vispw] + (numpasswd - len(vispw)) * ["🔑 <pw>"]
      )
      methods += f' 🔷 {a.filehash[:12].hex()}'
      for id in signatures:
        methods += f"  🖋️ {id}"
      if methods:
        lock += f"    {methods}"
      if args.outfile:
        lock += f"  💾 {args.outfile}\n"
      elif args.paste:
        lock += f"  📋 copied\n"
      out = f"\n\x1B[1m{lock}\x1B[0m\n"
      sys.stderr.write(out)
      sys.stderr.flush()
    if outf is not realoutf:
      outf.seek(0)
      data = outf.read()
      data = util.armor_encode(data)
    if outf is not realoutf:
      if args.paste:
        pyperclip.copy(f"```\n{data}\n```\n")
        return
      with realoutf:
        pretty = realoutf.isatty()
        if pretty:
          sys.stderr.write("\x1B[1;30m```\x1B[0;34m\n")
          sys.stderr.flush()
        try:
          realoutf.write(f"{data}\n".encode())
          realoutf.flush()
        finally:
          if pretty:
            sys.stderr.write("\x1B[1;30m```\x1B[0m\n")
            sys.stderr.flush()


def main_dec(args):
  if len(args.files) > 1:
    raise ValueError("Only one input file is allowed when decrypting.")
  # Ask for passphrase by default if no auth is specified
  if not (args.askpass or args.passwords or args.identities):
    args.askpass = 1
  identities = {key for keystr in args.identities for key in pubkey.read_sk_any(keystr)}
  identities = list(sorted(identities, key=str))
  infile = open(args.files[0], "rb") if args.files else sys.stdin.buffer
  # If ASCII armored or TTY, read all input immediately (assumed to be short enough)
  total_size = os.path.getsize(args.files[0]) if args.files else 0
  if infile.isatty():
    data = util.armor_decode(pyperclip.paste() if args.paste else tty.read_hidden("Encrypted message"))
    if not data:
      raise KeyboardInterrupt
    infile = BytesIO(data)
    total_size = len(data)
    del data
  elif 40 <= total_size <= ARMOR_MAX_SIZE:
    # Try reading the file as armored text rather than binary
    with infile:
      data = infile.read()
    try:
      infile = BytesIO(util.armor_decode(data.decode()))
    except Exception:
      infile = BytesIO(data)
  else:
    with suppress(OSError):
      infile = mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)
  with ThreadPoolExecutor(max_workers=4) as executor:
    pwhasher = lazyexec.map(executor, passphrase.pwhash, {util.encode(pwd) for pwd in args.passwords})
    def authgen():
      it = itertools.chain(identities, pwhasher, (passphrase.pwhash(passphrase.ask('Passphrase')[0]) for i in range(args.askpass)))
      while True:
        if sys.stderr.isatty():
          sys.stderr.write("Password hashing... ")
          sys.stderr.flush()
        try:
          pwhash = next(it)
        except StopIteration:
          break
        finally:
          if sys.stderr.isatty():
            sys.stderr.write("\r\x1B[0K")
            sys.stderr.flush()
        yield pwhash
    run_decryption(infile, args, authgen())


def main_benchmark(args):

  def noop_read(block):
    nonlocal dataleft
    block.pos = min(block.spaceleft, dataleft)
    dataleft -= block.pos

  datasize = int(1e9)
  a = Archive()

  # Count ciphertext size and preallocate mmapped memory
  dataleft = datasize
  size = sum(len(block) for block in encrypt_file((True, [], [], []), noop_read, a))
  ciphertext = mmap.mmap(-1, size)
  ciphertext[:] = bytes(size)

  rounds = 5
  enctotal = dectotal = 0
  for i in range(rounds):
    print("ENC", end="", flush=True)
    dataleft, size = datasize, 0
    t0 = perf_counter()
    for block in encrypt_file((True, [], [], []), noop_read, a):
      newsize = size + len(block)
      # There is a data copy here, similar to what happens on file.write() calls.
      ciphertext[size:newsize] = block
      size = newsize
    dur = perf_counter() - t0
    enctotal += dur
    print(f"{datasize / dur * 1e-6:6.0f} MB/s", end="", flush=True)

    print("  ➤   DEC", end="", flush=True)
    t0 = perf_counter()
    for data in decrypt_file(([], [], []), ciphertext, a):
      pass
    dur = perf_counter() - t0
    dectotal += dur
    print(f"{datasize / dur * 1e-6:6.0f} MB/s")

  ciphertext.close()
  print(f"Ran {rounds} cycles, each encrypting and then decrypting {datasize * 1e-6:.0f} MB in RAM.\n")
  print(f"Average encryption {rounds * size / enctotal * 1e-6:6.0f} MB/s")
  print(f"Average decryption {rounds * size / dectotal * 1e-6:6.0f} MB/s")
