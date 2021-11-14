from setuptools import find_packages, setup

setup(
  name="covert",
  author="Covert Encryption",
  description="File and message encryption program",
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
  install_requires=["pynacl>=1.4", "tqdm>=4.62", "msgpack>=1.0", "zxcvbn>=4.4"],
  include_package_data=True,
  entry_points=dict(console_scripts=["covert = covert.__main__:main"]),
)
