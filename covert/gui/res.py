from PySide6.QtGui import QPixmap

from covert.gui.util import datafile


class Icons:
  def __init__(self):
    self.logo = QPixmap(datafile('logo.png'))
    self.newicon = QPixmap(datafile('icons8-new-document-48.png')).scaled(48, 48)
    self.pasteicon = QPixmap(datafile('icons8-paste-48.png')).scaled(48, 48)
    self.openicon = QPixmap(datafile('icons8-cipherfile-64.png')).scaled(48, 48)
    self.fileicon = QPixmap(datafile('icons8-file-64.png')).scaled(24, 24)
    self.foldericon = QPixmap(datafile('icons8-folder-48.png')).scaled(24, 24)
    self.unlockicon = QPixmap(datafile('icons8-unlocked-48.png')).scaled(24, 24)
    self.lockicon = QPixmap(datafile('icons8-locked-48.png')).scaled(24, 24)
    self.keyicon = QPixmap(datafile('icons8-key-48.png')).scaled(24, 24)
    self.pkicon = QPixmap(datafile('icons8-link-48.png')).scaled(24, 24)
    self.signicon = QPixmap(datafile('icons8-signing-a-document-48.png')).scaled(24, 24)
    # Bottom toolbar icons
    self.attachicon = QPixmap(datafile('icons8-attach-48.png'))
    self.copyicon = QPixmap(datafile('icons8-copy-48.png'))
    self.saveicon = QPixmap(datafile('icons8-save-48.png'))


icons = None

def load():
  global icons
  icons =  Icons()
