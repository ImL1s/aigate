import Foundation

var info = kinfo_proc()
var size = MemoryLayout<kinfo_proc>.stride
var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, Int32(ProcessInfo.processInfo.processIdentifier)]
sysctlbyname("kern.proc.pid", &info, &size, nil, 0)
let isBeingDebugged = (info.kp_proc.p_flag & P_TRACED) != 0
if isBeingDebugged { exit(0) }
