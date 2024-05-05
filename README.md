# tas-rw-hook
An experiment of mapping CreateFile into memory, which (hopefully) will be useful for TASing
## Hooking
 - CreateFileA/CreateFileW
 - CloseHandle
 - ReadFile
 - WriteFile
 - SetFilePointer
 - MessageBoxA automaticly returns IDYES
## Problems
 - 32-bit only
 - Not all of the functions
 - Supports only one of ANSI and UNICODE
 - Doesn't check path conversion except case-sensitivity
## Apps Tested
 - I wanna be the boshy works
