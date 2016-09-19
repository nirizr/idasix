# idasix
IDAPython compatibility library. idasix aims to create a smooth ida development process and allow a single codebase to function with multiple IDA/IDAPython versions. It is supposed to be a very slim module that should be easily included in third party modules that would otherwise rather avoid dependecies, by directly including it inside thier repository.

# Inclusion in projects
One of idasix's goals is ease of incorporation inside any user project. Therefore, it is built as a single file that can be easily copied to any repository. For the same reason it is also built without directory hirarcies, so submoduling idasix and importing it will also work.

idasix is desinged not to break if multiple versions and copies are included in multiple projects. It protects itself from causing harm.

# Usage
once idasix is included in your project, it should be your source of IDA related modules.
Instead of `import idaapi` you should `from idasix import idaapi`.
Istead of `from PySide import QtGui` you should write `from idasix import QtGui`, which will provide you with a QtGui module regardless of IDA version (i.e. for both PySide and PyQt5).
