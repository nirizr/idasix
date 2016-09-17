IDA_SDK_VERSION = None
try:
  import ida_idaapi
  IDA_SDK_VERSION = ida_idaapi.IDA_SDK_VERSION
except ImportError:
  import idaapi
  IDA_SDK_VERSION = idaapi.IDA_SDK_VERSION

if not IDA_SDK_VERSION:
  raise Exception("Couldn't figure out IDA version")

# Handle different Qt versions. instead of:
# 1. `from PySide import QtCore, QtGui` or
# 2. `form PyQt5 import QtCore, QtWidgets`
# use:
# `from idasix import QtCore, QtWidgets`
QtGui = None
QtWidgets = None
QtCore = None
if IDA_SDK_VERSION >= 690:
  # IDA version >= 6.9
  from PyQt5 import QtCore, QtGui, QtWidgets
elif IDA_SDK_VERSION < 690:
  # IDA version <= 6.8
  from PySide import GtCore, QtGui
  QtWidgets = QtGui


if IDA_SDK_VERSION >= 695:
  import ida_idaapi
elif IDA_SDK_VERSION < 695:
  import idaapi
  ida_idaapi = idaapi


class Version(object):
  """Version related helper methods"""
  @staticmethod
  def idakernel64bit():
    """Returns True if running with a 64bit IDA kernel, False otherwise"""
    return ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL


class Fix(object):
  @staticmethod
  def idapackagespath():
    """Hack required in relatively old IDA linux/osx versions (around 6.4/5)
    to successfully load python packages installed in site-packages.

    IDA for linux/osx was using the machine's installed python instead of a
    packaged version, but that version was running without using site-packages.
    This made a user unable to install python packages and use them within ida
    without going through quite a bit of truble, without using this.
    """
    import sys
    import os
    sys.path += [os.path.join(sys.prefix, "Lib", "site-packages")]
