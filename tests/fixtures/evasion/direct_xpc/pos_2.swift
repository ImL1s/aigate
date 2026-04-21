let connection = NSXPCConnection(serviceName: "com.evil.helper")
connection.remoteObjectInterface = NSXPCInterface(with: EvilProtocol.self)
connection.resume()
