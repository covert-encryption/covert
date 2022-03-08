import os
import subprocess

from xdg import xdg_data_home

datadir = xdg_data_home() / "covert"
idfilename = datadir / "idstore"

def create_datadir():
  if not datadir.exists():
    datadir.mkdir(parents=True)
    if os.name == "posix":
      datadir.chmod(0o700)
      # Attempt to disable CoW (in particular with btrfs and zfs)
      ret = subprocess.run(["chattr", "+C", datadir], capture_output=True)  # nosec
