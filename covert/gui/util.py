import signal

import pkg_resources
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication


def datafile(name):
  return pkg_resources.resource_filename(__name__, f'data/{name}')


# Call this function in your main after creating the QApplication
def setup_interrupt_handling():
  """Setup handling of KeyboardInterrupt (Ctrl-C) for PyQt."""
  signal.signal(signal.SIGINT, _interrupt_handler)
  # Regularly run some (any) python code, so the signal handler gets a
  # chance to be executed:
  safe_timer(50, lambda: None)


# Define this as a global function to make sure it is not garbage
# collected when going out of scope:
def _interrupt_handler(signum, frame):
  """Handle KeyboardInterrupt: quit application."""
  QApplication.quit()


def safe_timer(timeout, func, *args, **kwargs):
  """
    Create a timer that is safe against garbage collection and overlapping
    calls. See: http://ralsina.me/weblog/posts/BB974.html
    """

  def timer_event():
    try:
      func(*args, **kwargs)
    finally:
      QTimer.singleShot(timeout, timer_event)

  QTimer.singleShot(timeout, timer_event)
