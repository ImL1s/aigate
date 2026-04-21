xpc_connection_t conn = xpc_connection_create_mach_service("com.evil.xpc", queue, 0);
xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {});
xpc_connection_resume(conn);
