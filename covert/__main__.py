import os
import sys
from typing import NoReturn
import colorama
import covert
from covert.cli import main_benchmark, main_dec, main_edit, main_enc

basicusage = """\
Usage:
  covert enc [files] [recipients] [signatures] [-A | -o unsuspicious.dat [-a]]
  covert dec [-A | unsuspicious.dat] [-i id_ed25519] [-o filesfolder]
  covert edit unsuspicious.dat — change text in a passphrase-protected archive
"""

shorthdrhelp = f"""\
{basicusage}\
  covert help — show full command line help

Running covert enc/dec without arguments asks for a password and a message.
Files and folders get attached together with a message if 'enc -' is specified.
"""

# Short command line help
shortenchelp = """\
  -p                Passphrase recipient (default)
  --wide-open       Anyone can open the file (no recipients)
  -r PKEY -R FILE   Recipient pubkey, .pub file or github:username
  -i SKEY           Sign with a secret key (string token or id file)
  -A                Auto copy&paste: ciphertext is copied
  -o FILENAME       Encrypted file to output (binary unless -a is used)
  --pad PERCENT     Preferred padding amount (default 5 %)
"""

shortdechelp = """\
  -A                Auto copy&paste: ciphertext is pasted
  -i SKEY           Decrypt with secret key (token or file)
  -o FILEFOLDER     Extract any attached files to
"""

introduction = f"""\
Covert {covert.__version__} - A file and message encryptor with strong anonymity
 💣  Things encrypted with this developer preview mayn't be readable evermore
"""

shortcmdhelp = f"""\
{introduction}
{shorthdrhelp}
{shortenchelp}
{shortdechelp}
"""

# Full command line help
hdrhelp = f"""\
{basicusage}\
  covert help — show full command line help
  covert benchmark — run a performance benchmark for decryption and encryption

Running covert enc/dec without arguments asks for a password and a message.
Files and folders get attached together with a message if 'enc -' is specified.
"""

enchelp = f"""\
Encryption options:
{shortenchelp}\
  -a                Write base64 encoded output when -o is used
"""

dechelp = f"""\
Decryption options:
{shortdechelp}\
"""

keyformatshelp = """\
Supported key formats:

* age1: To generate a key, run: age-keygen
* ssh-ed25519: To generate a key, run: ssh-keygen -t ed25519
"""

exampleshelp = """\
Examples:

* To encrypt a message using an ssh-ed25519 public key, run:
  - covert enc -R ~/.ssh/myfriend.pub -o file
  - covert enc -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1hd2CrH/pexUjxNfqhHAaKqGwSmn0+sO/YUXVm9Gt1" -o file

* To decrypt a message using a private ssh-ed25519 key file, run:
  - covert dec -i ~/.ssh/id_ed25519 file
"""

cmdhelp = f"""\
{introduction}
{hdrhelp}
{enchelp}
{dechelp}
{keyformatshelp}
{exampleshelp}
"""

class Args:

  def __init__(self):
    self.mode = None
    self.files = []
    self.wideopen = None
    self.askpass = 0
    self.passwords = []
    self.recipients = []
    self.recipfiles = []
    self.outfile = []
    self.identities = []
    self.padding = "5"
    self.armor = None
    self.paste = None
    self.debug = None


encargs = dict(
  askpass='-p --passphrase'.split(),
  passwords='--password'.split(),
  wideopen='--wide-open'.split(),
  recipients='-r --recipient'.split(),
  recipfiles='-R --keyfile --recipients-file'.split(),
  identities='-i --identity'.split(),
  outfile='-o --out --output'.split(),
  armor='-a --armor'.split(),
  paste='-A'.split(),
  padding='--pad --padding'.split(),
  debug='--debug'.split(),
)

decargs = dict(
  askpass='-p --passphrase'.split(),
  passwords='--password'.split(),
  identities='-i --identity'.split(),
  outfile='-o --out --output'.split(),
  paste='-A'.split(),
  debug='--debug'.split(),
)

editargs = dict(debug='--debug'.split(),)
benchargs = dict(debug='--debug'.split(),)

# TODO: Put mode args and help here as well
modes = {
  "enc": main_enc,
  "dec": main_dec,
  "edit": main_edit,
  "benchmark": main_benchmark,
}

def print_help(modehelp: str = None):
  if modehelp is None:
    modehelp = shortcmdhelp
  first, rest = modehelp.rstrip().split('\n', 1)
  print(f'\x1B[1;44m{first:78}\x1B[0m\n{rest}')
  sys.exit(0)

def print_version():
  print(shortcmdhelp.split('\n')[0])
  sys.exit(0)

def needhelp(av):
  """Check for -h and --help but not past --"""
  for a in av:
    if a == '--': return False
    if a.lower() in ('-h', '--help'): return True
  return False

def argparse():
  # Custom parsing due to argparse module's limitations
  av = sys.argv[1:]
  if not av:
    print_help()

  if any(a.lower() in ('-v', '--version') for a in av):
    print_version()

  ad = {}
  args = Args()
  modehelp = None
  # Separate mode selector from other arguments
  if av[0].startswith("-") and len(av[0]) > 2 and not needhelp(av):
      av.insert(1, f'-{av[0][2:]}')
      av[0] = av[0][:2]

  # Support a few other forms for Age etc. compatibility (but only as the first arg)
  if av[0] in ('enc', 'encrypt', '-e'):
    args.mode, ad, modehelp = 'enc', encargs, f"{hdrhelp}\n{enchelp}"
  elif av[0] in ('dec', 'decrypt', '-d'):
    args.mode, ad, modehelp = 'dec', decargs, f"{hdrhelp}\n{dechelp}"
  elif av[0] in ('edit', ):
    args.mode, ad, modehelp = 'edit', editargs, hdrhelp
  elif av[0] in ('bench', 'benchmark'):
    args.mode, ad, modehelp = 'benchmark', benchargs, hdrhelp
  elif av[0] in ('help', ):
    args.mode, ad, modehelp = 'help', {}, cmdhelp

  if args.mode == 'help' or needhelp(av):
    print_help(modehelp=modehelp)

  if args.mode is None:
    sys.stderr.write(' 💣  Invalid or missing command (enc/dec/edit/benchmark/help).\n')
    sys.exit(1)

  aiter = iter(av[1:])
  longargs = [flag[1:] for switches in ad.values() for flag in switches if flag.startswith("--")]
  shortargs = [flag[1:] for switches in ad.values() for flag in switches if not flag.startswith("--")]
  for a in aiter:
    aprint = a
    if not a.startswith('-'):
      args.files.append(a)
      continue
    if a == '-':
      args.files.append(True)
      continue
    if a == '--':
      args.files += aiter
      break
    if a.startswith('--'):
      a = a.lower()
    if not a.startswith('--') and len(a) > 2:
      if any(arg not in shortargs for arg in list(a[1:])):
        falseargs = [arg for arg in list(a[1:]) if arg not in shortargs]
        sys.stderr.write(f' 💣  {falseargs} is not an argument: covert {args.mode} {a}\n')
        sys.exit(1)
      a = [f'-{shortarg}' for shortarg in list(a[1:]) if shortarg in shortargs]
    if isinstance(a, str):
      a = [a]
    for i, av in enumerate(a):
      argvar = next((k for k, v in ad.items() if av in v), None)
      if isinstance(av, int):
        continue
      if argvar is None:
        sys.stderr.write(f'{modehelp}\n 💣  Unknown argument: covert {args.mode} {aprint}\n')
        sys.exit(1)
      try:
        var = getattr(args, argvar)
        if isinstance(var, list):
          var.append(next(aiter))
        elif isinstance(var, str):
          setattr(args, argvar, next(aiter))
        elif isinstance(var, int):
          setattr(args, argvar, var + 1)
        else:
          setattr(args, argvar, True)
      except StopIteration:
        sys.stderr.write(f'{modehelp}\n 💣  Argument parameter missing: covert {args.mode} {aprint} …\n')
        sys.exit(1)

  return args


def main() -> NoReturn:
  """
  The main CLI entry point.

  Consider calling covert.cli.main* or other modules directly if you use from Python code.

  System exit codes:
  * 0 The requested function was completed successfully
  * 1 CLI argument error
  * 2 I/O error (broken pipe, not other types currently)
  * 10-99 Normal errors, authentication failures, corrupted data, ... (currently 10 for all)

  :raises SystemExit: on normal exit or any expected error, including KeyboardInterrupt
  :raises Exception: on unexpected error (report a bug), or on any error with `--debug`
  """
  colorama.init()
  # CLI argument processing
  args = argparse()
  if len(args.outfile) > 1:
    raise ValueError('Only one output file may be specified')
  args.outfile = args.outfile[0] if args.outfile else None

  # A quick sanity check, not entirely reliable
  if args.outfile in args.files:
    raise ValueError('In-place operation is not supported, cannot use the same file as input and output.')

  # Run the mode-specific main function
  if args.debug:
    modes[args.mode](args)  # --debug makes us not catch errors
    sys.exit(0)
  try:
    modes[args.mode](args)  # Normal run
  except ValueError as e:
    sys.stderr.write(f"Error: {e}\n")
    sys.exit(10)
  except BrokenPipeError:
    sys.stderr.write('I/O error (broken pipe)\n')
    sys.exit(3)
  except KeyboardInterrupt:
    sys.stderr.write("Interrupted.\n")
    sys.exit(2)
  sys.exit(0)

if __name__ == "__main__":
  main()
