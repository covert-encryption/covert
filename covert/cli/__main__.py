import sys
from typing import NoReturn

import colorama

from covert.cli.args import argparse
from covert.cli.bench import main_bench
from covert.cli.dec import main_dec
from covert.cli.edit import main_edit
from covert.cli.enc import main_enc
from covert.cli.id import main_id

modes = {
  "enc": main_enc,
  "dec": main_dec,
  "edit": main_edit,
  "id": main_id,
  "bench": main_bench,
}


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
