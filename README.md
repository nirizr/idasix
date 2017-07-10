# idasix
IDAPython compatibility library. idasix aims to create a smooth ida development process and allow a single codebase to function with multiple IDA/IDAPython versions. It is supposed to be a very slim module that should be easily included in third party modules that would otherwise rather avoid dependencies, by directly including it inside their repository.

# Inclusion in projects
One of idasix's goals is ease of incorporation inside any user project. Therefore, it is built as a single file that can be easily copied to any repository. For the same reason it is also built without directory hierarchies, so submoduling idasix and importing it will also work. It is also possible to provide idasix as an independent IDA plugin, in which case idasix will automatically provide it's functionalities without being imported from any specific idapython plugin.

idasix is designed not to break if multiple versions and copies are included in multiple projects. It protects itself from causing harm.

# Usage
once idasix is included in your project, it should be your source of IDA related modules.
While the modules you're used to will be automatically loaded by idasix, it is encouraged to import from it instead of original modules when manually importing.
Instead of `import idaapi` you should use `from idasix import idaapi`.
Instead of `from PySide import QtGui` you should write `from idasix import QtGui`, which will provide you with a QtGui module regardless of IDA version (i.e. for both PySide and PyQt5).

# Currently addressed issues
This list tries being up to date and include all currently addressed IDA issues, users are encouraged to raise issues to request additional IDA version incompatibility problems.

Currently addressed issues are:

1. `action_handler_t` is not a python class (Doesn't inherit `Object`) before IDA version 6.95. idasix makes sure `action_handler_t` always inherits `Object`, which enables some more python magic.
2. Linux IDA versions have an issue with using packages installed by the external python interpreter. This is a mishap by IDA. idasix adds the right "site-packages" directory to the list of python packages.
3. With IDA version 6.9, PySide (a python Qt4 library) was replaced with pyqt (using newer Qt5). idasix exposes one interface (`form idasix import QtGui`) to the appropriate version and tries mitigating some of the differences between Qt5 and 4.
4. Expose `QtCore.Signal` and `QtCore.Slot` from `idasix.QtCore` in IDA versions using pyqt5.

# Projects using idasix

1. [[REmatch](https://github.com/nirizr/rematch)] - A binary matching framework that actually works.
