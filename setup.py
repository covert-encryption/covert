from setuptools import find_packages, setup

setup(
  name="covert",
  author="Covert Encryption",
  author_email="covert-encryption@users.noreply.github.com",
  description="File and message encryption GUI and CLI",
  long_description=open("README.md").read(),
  long_description_content_type="text/markdown",
  url="https://github.com/covert-encryption/covert",
  use_scm_version=True,
  setup_requires=["setuptools_scm"],
  packages=find_packages(),
  python_requires=">=3.9",
  classifiers=[
    "Programming Language :: Python :: 3",
    "License :: OSI Approved :: MIT License",
    "License :: Public Domain",
    "Operating System :: OS Independent",
  ],
  install_requires=[
    "bcrypt>=3.0.0",
    "colorama>=0.4",
    "cryptography>=35",
    "pynacl>=1.4",
    "tqdm>=4.62",
    "msgpack>=1.0",
    "pyperclip>=1.8",
    "zxcvbn-covert>=5.0",
  ],
  extras_require={
    "gui": ["pyside6>=6.2.1"],
    "test": ["pytest", "pytest-sugar", "pytest-mock", "coverage", "mypy", "bandit"],
    "dev": ["tox", "isort", "yapf"],
  },
  include_package_data=True,
  entry_points=dict(
    console_scripts=["covert = covert.__main__:main"],
    gui_scripts=["qcovert = covert.gui.__main__:main [gui]"],
  ),
)
