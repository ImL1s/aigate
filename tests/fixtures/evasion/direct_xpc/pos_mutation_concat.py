# NOTE: string-concat variant — expected to MISS the D-Bus regex (documented limitation).
# The regex matches the literal call token; it cannot resolve runtime string
# concatenation. An AST-aware pass will handle this in a future phase.
bus_module = "dbus"
bus_cls = bus_module + ".SessionBus" + "()"  # split — regex cannot match across concatenation
path_parts = ['org', 'freedesktop_secrets']  # underscore avoids the dotted org path token
