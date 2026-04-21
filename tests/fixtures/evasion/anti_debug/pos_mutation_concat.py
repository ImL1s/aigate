# NOTE: string-concat variant — expected to MISS the self-trace regex (documented limitation).
# The static regex matches the literal constant name; it cannot resolve runtime
# string concatenation. An AST-aware pass will handle this in a future phase.
trace_const = "PTRACE_" + "TRACEME"  # split — no literal match possible
invoke_trace = getattr(libc, "ptrace")  # getattr avoids literal call syntax
invoke_trace(trace_const, 0, 0, 0)
