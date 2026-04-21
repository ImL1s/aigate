import dbus  # unused import — no bus instantiation or method call
# Package lists dbus as an optional dependency but never calls SessionBus() or SystemBus()
def get_dbus_version():
    return "1.14.0"
