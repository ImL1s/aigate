import dbus
bus = dbus.SessionBus()
iface = bus.get_object('org.freedesktop.secrets', '/')
