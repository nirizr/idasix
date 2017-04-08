IDA_SDK_VERSION = None
try:
  import ida_pro
  IDA_SDK_VERSION = ida_pro.IDA_SDK_VERSION
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
  _ = QtCore
elif IDA_SDK_VERSION < 690:
  # IDA version <= 6.8
  from PySide import QtCore, QtGui
  QtWidgets = QtGui
  _ = QtCore


modules = ['ida_idaapi', 'ida_auto', 'ida_dbg', 'ida_diskio', 'ida_entry',
           'ida_enum', 'ida_expr', 'ida_fixup', 'ida_frame', 'ida_funcs',
           'ida_gdl', 'ida_ida', 'ida_bytes', 'ida_idd', 'ida_idp',
           'ida_kernwin', 'ida_lines', 'ida_loader', 'ida_moves', 'ida_nalt',
           'ida_name', 'ida_netnode', 'ida_offset', 'ida_pro', 'ida_search',
           'ida_segment', 'ida_srarea', 'ida_struct', 'ida_typeinf', 'ida_ua',
           'ida_xref', 'ida_graph']
if IDA_SDK_VERSION >= 695:
  import ida_idaapi
  import ida_pro
  import ida_kernwin
  for module in modules:
    globals()[module] = __import__(module)
elif IDA_SDK_VERSION < 695:
  import sys

  ida_idaapi = idaapi
  ida_pro = idaapi
  ida_kernwin = idaapi
  for module in modules:
    sys.modules[module] = idaapi


class Fix(object):
  @staticmethod
  def packagespath():
    """Hack required in relatively old IDA linux/osx versions (around 6.4/5)
    to successfully load python packages installed in site-packages.

    IDA for linux/osx was using the machine's installed python instead of a
    packaged version, but that version was running without using
    site-packages. This made a user unable to install python packages and use
    them within ida without going through quite a bit of truble, without
    using this.
    """
    import sys
    import os
    sys.path += [os.path.join(sys.prefix, "Lib", "site-packages")]

  @staticmethod
  def actionhandlerobject():
    """Before IDA 6.95, `action_handler_t` does not inherit from `object` and
    that makes some python magic fail. Since 6.95 `action_handler_t` inherits
    `object`. This fix makes reachable `action_handler_t` inherit from
    `object` before 6.95.
    """
    # this makes sure we have an `object` inheriting action_handler_t
    # regardless of version
    if IDA_SDK_VERSION >= 695:
      action_handler_t_object = ida_kernwin.action_handler_t
    else:
      class action_handler_t_object(object, ida_kernwin.action_handler_t):
        """A base object created by `idasix.Fix.actionhandlerobject` to inherit
        `object`."""
        pass

    class action_handler_metaclass(type):
      def __new__(meta, name, bases, dct):
        bases = tuple(base for base in bases if base is not object)
        return super(action_handler_metaclass, meta).__new__(meta, name,
                                                             bases, dct)

    class action_handler_t_objprotector(action_handler_t_object):
      """An object inheriting from ``idasix.Fix.action_handler_t_object` that
      uses a metaclass to protect against multiple `object` inharitance. This
      makes sure that `object` is only inherited once even when a user
      manually inherits from it again"""
      __metaclass__ = action_handler_metaclass

    ida_kernwin.action_handler_t = action_handler_t_objprotector

  @staticmethod
  def qtsignalslot():
    """While pre-6.8 qt4 library pyside exposted `Qtcore.Signal` and
    `QtCore.Slot`, new pyqt library exposes those same methods as
    `QtCore.pyqtSignal` and `QtCore.pyqtSlot`. This fix makes sure
    `Qtcore.Signal` and `QtCore.Slot` are always available"""
    if IDA_SDK_VERSION >= 690:
      QtCore.Signal = QtCore.pyqtSignal
      QtCore.Slot = QtCore.pyqtSlot
    elif IDA_SDK_VERSION < 690:
      pass


Fix.packagespath()
Fix.actionhandlerobject()
Fix.qtsignalslot()
