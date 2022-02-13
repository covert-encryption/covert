import subprocess

from xdg import xdg_config_home

confdir = xdg_config_home() / "covert"
idfilename = confdir / "idstore"

def create_confdir():
  if not confdir.exists():
    confdir.mkdir(parents=True)
    if os.name == "posix":
      confdir.chmod(0o700)
      # Attempt to disable CoW (in particular with btrfs and zfs)
      ret = subprocess.run(["chattr", "+C", confdir], capture_output=True)  # nosec
