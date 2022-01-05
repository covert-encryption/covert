from contextlib import suppress

from PySide6.QtCore import QRect, Qt, QTimer, Slot
from PySide6.QtGui import QAction, QGuiApplication, QKeySequence
from PySide6.QtWidgets import *

from covert import passphrase, util
from covert.gui import res
from covert.gui.decrypt import DecryptView
from covert.gui.encrypt import NewMessageView
from covert.gui.util import setup_interrupt_handling


class App(QApplication):
  def __init__(self):
    QApplication.__init__(self, [])
    setup_interrupt_handling()
    res.load()

    # Override CLI password asking with GUI version
    passphrase.ask = self.askpass

    self.setApplicationName('Covert Encryption')
    self.setWindowIcon(res.icons.logo)
    self.windows = set()
    self.new_window()

  def askpass(self, prompt, create=False):
    window = next(iter(self.windows))  # FIXME: Keep track of active mainwindow in case there are multiple
    pw, ok = QInputDialog.getText(window, "Covert Encryption", f"{prompt}:", QLineEdit.Password, "")
    if not ok: raise ValueError(f"Needed {prompt}")
    return util.encode(pw), True

  @Slot()
  def new_window(self):
    self.windows.add(MainWindow(self))

class MainWindow(QMainWindow):
  def __init__(self, app):
    QMainWindow.__init__(self)
    self.setWindowTitle("Covert Encryption")
    self.app = app

    # Menu
    self.menu = self.menuBar()
    self.file_menu = self.menu.addMenu("File")

    new_action = QAction("&New Window", self)
    new_action.setShortcut(QKeySequence.New)
    new_action.triggered.connect(app.new_window)
    self.file_menu.addAction(new_action)

    new_action = QAction("Close Window", self)
    new_action.setShortcut(QKeySequence.Close)
    new_action.triggered.connect(self.close)
    self.file_menu.addAction(new_action)

    exit_action = QAction("E&xit", self)
    exit_action.setShortcut(QKeySequence.Quit)
    exit_action.triggered.connect(app.quit)
    self.file_menu.addAction(exit_action)

    # Toolbar
    self.addToolBar(Qt.TopToolBarArea, MainToolbar(self))

    # Status Bar
    self.status = self.statusBar()

    self.setCentralWidget(WelcomeView(self))
    self.show()

  def flash(self, message, duration=2.0):
    self.status.showMessage(message)
    QTimer.singleShot(1000 * duration, lambda: self.status.showMessage(""))

  @Slot()
  def encrypt_new(self):
    self.setCentralWidget(NewMessageView(self))

  @Slot()
  def decrypt_paste(self):
    try:
      text = QGuiApplication.clipboard().text()
      if not text:
        raise ValueError("Nothing in clipboard to paste")
      data = util.armor_decode(text)
      self.decrypt(data)
    except ValueError as e:
      self.flash(str(e))

  @Slot()
  def decrypt_file(self):
    try:
      file = QFileDialog.getOpenFileName(self, "Covert - Open file", "", "Covert Binary or Armored (*)")[0]
      if not file:
        return
      # TODO: Implement in a thread using mmap instead
      with open(file, "rb") as f:
        data = f.read()
      if 40 <= len(data) <= 2 * util.ARMOR_MAX_SIZE:
        # Try reading the file as armored text rather than binary
        with suppress(ValueError):
          data = util.armor_decode(data.decode())
      self.decrypt(data)
    except ValueError as e:
      self.flash(str(e))

  def decrypt(self, infile):
    d = DecryptView(self, infile)
    if not d.blockstream.header.key:
      # Only display that view if auth is needed; otherwise the DecryptView already
      # set the ArchiveView to display contents and we should do nothing here.
      self.setCentralWidget(d)

class MainToolbar(QToolBar):
  def __init__(self, app):
    QToolBar.__init__(self)
    self.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
    self.newbutton = self.addAction(res.icons.newicon, "New Message")
    self.addSeparator()
    self.pastebutton = self.addAction(res.icons.pasteicon, "Paste Armored")
    self.openbutton = self.addAction(res.icons.openicon, "Open Covert File")
    self.newbutton.triggered.connect(app.encrypt_new)
    self.pastebutton.triggered.connect(app.decrypt_paste)
    self.openbutton.triggered.connect(app.decrypt_file)

class WelcomeView(QWidget):
  def __init__(self, app):
    QWidget.__init__(self)
    self.logo = QLabel()
    self.logo.setAlignment(Qt.AlignTop)
    self.logo.setGeometry(QRect(0, 0, 128, 128))
    self.logo.setPixmap(res.icons.logo)

    self.text = QLabel("<h1>Covert Encryption</h1><p>Choose a function on the top toolbar.<p><b>New Message</b> to create a new covert archive,<br><b>Paste Armored</b> or <b>Open Covert File</b> to decrypt.")
    self.layout = QHBoxLayout(self)
    self.layout.addWidget(self.logo)
    self.layout.addWidget(self.text)
