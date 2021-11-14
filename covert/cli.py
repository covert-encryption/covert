import mmap
import os
from contextlib import suppress
from io import BytesIO
from pathlib import Path
from sys import stderr, stdin, stdout
from time import perf_counter

from tqdm import tqdm

from covert import passphrase, pubkey, util
from covert.archive import Archive
from covert.blockstream import decrypt_file, encrypt_file

ARMOR_MAX_SIZE = 32 << 20  # If output is a file (limit our memory usage)
TTY_MAX_SIZE = 100 << 10  # If output is a tty (limit too lengthy spam)


def run_decryption(infile, args, passwords, identities):
  a = Archive()
  progress = None
  outdir = None
  f = None
  messages = []
  for data in a.decode(decrypt_file((passwords, identities), infile)):
    if isinstance(data, dict):
      # Header parsed, check the file list
      for i, infile in enumerate(a.flist):
        if 'n' not in infile:
          if 's' not in infile or infile['s'] > TTY_MAX_SIZE:
            infile['n'] = f'noname.{i+1:03}'
            infile['renamed'] = True
        elif infile['n'][0] == '.':
          infile['n'] = f"noname.{i+1:03}{infile['n']}"
          infile['renamed'] = True
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
            prev['n'] = f"noname.{pidx + 1:03}"
            prev['renamed'] = True
            with get_writable_file(prev['n']) as f2:
              f2.write(data)
        f.close()
        f = None
      if prev and 'n' in prev:
        n = prev['n']
        s = prev['s']
        r = '<renamed>' if 'renamed' in prev else ''
        progress.write(f'{s:15,d} 📄 {n:60}{r}', file=stderr)
      if a.curfile:
        n = a.curfile.get('n', '')
        if not n and a.curfile.get('s', float('inf')) < TTY_MAX_SIZE:
          f = BytesIO()
        elif args.outfile:
          if not outdir:
            outdir = Path(args.outfile).resolve()
            outdir.mkdir(parents=True, exist_ok=True)
            progress.write(f" ▶️ \x1B[1;34m  Extracting to \x1B[1;37m{outdir}\x1B[0m", file=stderr)
          name = outdir.joinpath(n)
          if not name.resolve().is_relative_to(outdir) or name.is_reserved():
            progress.close()
            raise ValueError(f'Invalid filename {n!r}')
          name.parent.mkdir(parents=True, exist_ok=True)
          f = open(name, 'wb')
        elif outdir is None:
          outdir = False
          progress.write(" ▶️ \x1B[1;34m  The archive contains files. To extract, use \x1B[1;37m-o PATH\x1B[0m", file=stderr)

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
  for i, m in enumerate(messages):
    if stdout.isatty():
      stderr.write("\x1B[1m 💬\n\x1B[1;34m")
      stderr.flush()
      # Replace dangerous characters
      m = ''.join(c if c.isprintable() or c in ' \t\n' else f'\x1B[31m{repr(c)[1:-1]}\x1B[1;34m' for c in m)
    try:
      print(m)
    finally:
      try:
        if stdout.isatty():
          stderr.write(f"\x1B[0m")
          stderr.flush()
      except Exception:
        pass


def main_enc(args):
  vispw = []
  padding = .01 * float(args.padding) if args.padding is not None else .05
  if not 0 <= padding <= 3.0:
    raise ValueError('Invalid padding specified. The valid range is 0 to 300 %.')
  passwords, vispw = [], []
  if not (args.askpass or args.passwords or args.recipients or args.recipfiles or args.args.wideopen):
    args.askpass = 1
  l = args.askpass + len(args.passwords)
  for i in range(args.askpass):
    num = f" {i+1}/{l}" if l > 1 else ""
    pw, visible = passphrase.ask(f"New passphrase{num}", create=True)
    passwords.append(pw)
    if visible:
      vispw.append(pw)
  passwords += args.passwords
  # Convert recipient definitions into keys
  recipients = [pubkey.decode_pk(keystr) for keystr in args.recipients]
  for fn in args.recipfiles:
    recipients += pubkey.read_pk_file(fn)
  # Unique recipient keys sorted by keystr
  l = len(recipients)
  recipients = list(sorted(set(recipients), key=str))
  # Signatures
  identities = [key for keystr in args.identities for key in pubkey.read_sk_any(keystr)]
  signatures = identities = list(sorted(set(identities), key=str))
  if len(recipients) < l:
    strerr.write(' ⚠️  Duplicate recipient keys dropped.\n')
  # Input files
  if not args.files or True in args.files:
    if stdin.isatty():
      stderr.write(
        f'\x1B[?1049h\x1B[1;1H\x1B[1m   〰 ENTER MESSAGE 〰 \x1B[0m  (Ctrl+{"Z" if os.name == "nt" else "D"} to finish)\n'
      )
      try:
        stin = stdin.read(TTY_MAX_SIZE)
      finally:
        stderr.write(f"\x1B[?1049l\n")
      if len(stin) == TTY_MAX_SIZE:
        raise ValueError("Too large input by stdin TTY. Use files or pipes instead.")
      # Prune surrounding whitespace
      stin = '\n'.join([l.rstrip() for l in stin.split('\n')]).strip('\n')
      stin = util.encode(stin)
    else:
      stin = stdin.buffer
    args.files = [stin] + [f for f in args.files if f != True]
  a = Archive()
  a.file_index(args.files)
  # Output files
  realoutf = open(args.outfile, "wb") if args.outfile else stdout.buffer
  if args.armor or not args.outfile and stdout.isatty():
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
      s = prev.get('s')
      n = prev.get('n')
      progress.write(f'{s:15,d} 📄 {n:60}' if n else f'{s:15,d} 💬 <message>', file=stderr)
    if not cur:
      a.random_padding(padding)
      progress.write(f'{a.padding:15,d} ⬛ <padding>', file=stderr)
  a.nextfilecb = nextfile_callback
  # Main processing
  with outf:
    with tqdm(
      total=a.total_size, delay=1.0, ncols=78, unit='B', unit_scale=True, bar_format="{l_bar}         {bar}{r_bar}"
    ) as progress:
      for block in encrypt_file((args.wideopen, passwords, recipients, signatures), a.encode):
        progress.update(len(block))
        outf.write(block)
    # Pretty output printout
    if stderr.isatty():
      # Print a list of files
      lock = " 🔓 wide-open" if args.wideopen else " 🔒 covert"
      methods = "  ".join(
        [f"🔗 {r}" for r in recipients] + [f"🔑 {a}" for a in vispw] + (len(passwords) - len(vispw)) * ["🔑 <pw>"]
      )
      for id in signatures:
        methods += f"  ✍️  {id}"
      if methods:
        lock += f"    {methods}"
      if args.outfile:
        lock += f"  💾 {args.outfile}\n"
      out = f"\n\x1B[1m{lock}\x1B[0m\n"
      stderr.write(out)
      stderr.flush()
    if outf is not realoutf:
      outf.seek(0)
      data = outf.read()
    if outf is not realoutf:
      with realoutf:
        if realoutf.isatty():
          stderr.write("\x1B[1;30m```\x1B[0;34m\n")
          stderr.flush()
        try:
          data = util.armor_encode(data)
          realoutf.write(data + b"\n")
          realoutf.flush()
        finally:
          try:
            if realoutf.isatty():
              stderr.write("\x1B[1;30m```\x1B[0m\n")
              stderr.flush()
          except Exception:
            pass


def main_dec(args):
  if len(args.files) > 1:
    raise ValueError("Only one input file is allowed when decrypting.")
  identities = [key for keystr in args.identities for key in pubkey.read_sk_any(keystr)]
  identities = list(sorted(set(identities), key=str))
  infile = open(args.files[0], "rb") if args.files else stdin.buffer
  # If ASCII armored or TTY, read all input immediately (assumed to be short enough)
  total_size = os.path.getsize(args.files[0]) if args.files else 0
  if args.armor or infile.isatty():
    if infile.isatty():
      stderr.write("\x1B[?1049h\x1B[1;1H\x1B[1m〰 COVERT 〰\x1B[0m   (paste and press enter)\x1B[1;30m\n")
      stderr.flush()
    try:
      data = b""
      while True:
        line = input().strip().encode()
        if not line: break
        data += line
      data = util.armor_decode(data)
      total_size = len(data)
    except Exception as e:
      raise ValueError(f"Incomplete or malformed data. {e} {len(data)}\n{line}")
    finally:
      with suppress(Exception):
        if infile.isatty():
          stderr.write("\x1B[0m\x1B[2J\x1B[?1049l")
          stderr.flush()
    if not data:
      raise ValueError("No input, aborted.")
    infile = BytesIO(data)
    del data
  elif 40 <= total_size <= ARMOR_MAX_SIZE:
    # Try reading the file as armored text rather than binary
    with infile:
      data = infile.read()
    try:
      infile = BytesIO(util.armor_decode(data))
    except Exception:
      infile = BytesIO(data)
  else:
    with suppress(OSError):
      infile = mmap.mmap(infile.fileno(), 0, access=mmap.ACCESS_READ)
  run_decryption(infile, args, args.passwords, identities)


def main_benchmark(args):

  def noop_read(block):
    nonlocal dataleft
    block.pos = min(block.spaceleft, dataleft)
    dataleft -= block.pos

  datasize = int(2e9)

  # Count ciphertext size and preallocate mmapped memory
  dataleft = datasize
  size = sum(len(block) for block in encrypt_file((True, [], [], []), noop_read))
  ciphertext = mmap.mmap(-1, size)
  ciphertext[:] = bytes(size)

  rounds = 5
  enctotal = dectotal = 0
  for i in range(rounds):
    print("ENC", end="", flush=True)
    dataleft, size = datasize, 0
    t0 = perf_counter()
    for block in encrypt_file((True, [], [], []), noop_read):
      newsize = size + len(block)
      # There is a data copy here, similar to what happens on file.write() calls.
      ciphertext[size:newsize] = block
      size = newsize
    dur = perf_counter() - t0
    enctotal += dur
    print(f"{datasize / dur * 1e-6:6.0f} MB/s", end="", flush=True)

    print("  ➤   DEC", end="", flush=True)
    t0 = perf_counter()
    for data in decrypt_file(([], [], []), ciphertext):
      pass
    dur = perf_counter() - t0
    dectotal += dur
    print(f"{datasize / dur * 1e-6:6.0f} MB/s")

  ciphertext.close()
  print(f"Ran {rounds} cycles, each encrypting and then decrypting {datasize * 1e-6:.0f} MB in RAM.\n")
  print(f"Average encryption {rounds * size / enctotal * 1e-6:6.0f} MB/s")
  print(f"Average decryption {rounds * size / dectotal * 1e-6:6.0f} MB/s")
