import ctypes
libc = ctypes.CDLL("libc.so.6")
PTRACE_TRACEME = 0
libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
