import Foundation
import Darwin

/// A running process, as seen through libproc and sysctl. Reading other users'
/// processes (root daemons) mostly fails without privileges; that's fine, because
/// the malware this looks for runs as the logged-in user.
struct RunningProcess: Hashable {
    let pid: pid_t
    let ppid: pid_t
    let uid: uid_t
    /// When the process started (seconds since 1970), used to tell PIDs apart when they're reused.
    let started: UInt64
    let path: String
    let arguments: [String]

    var name: String { (path as NSString).lastPathComponent }
    var commandLine: String { arguments.joined(separator: " ") }
    /// A key that stays unique even when macOS reuses a PID.
    var key: String { "\(pid)-\(started)" }
}

enum ProcessList {
    /// PIDs of every process on the system.
    static func allPIDs() -> [pid_t] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let filled = pids.withUnsafeMutableBufferPointer { buffer in
            proc_listallpids(buffer.baseAddress, Int32(buffer.count * MemoryLayout<pid_t>.size))
        }
        guard filled > 0 else { return [] }
        return Array(pids.prefix(Int(filled))).filter { $0 > 0 }
    }

    /// Full details of one process, or nil if it's gone or can't be read.
    static func info(_ pid: pid_t) -> RunningProcess? {
        var bsd = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, size) == size else { return nil }
        let path = executablePath(pid) ?? ""
        guard !path.isEmpty else { return nil }
        return RunningProcess(pid: pid,
                              ppid: pid_t(bsd.pbi_ppid),
                              uid: bsd.pbi_uid,
                              started: bsd.pbi_start_tvsec,
                              path: path,
                              arguments: arguments(pid) ?? [path])
    }

    static func executablePath(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }

    /// argv of a process via KERN_PROCARGS2: [argc][exec path][padding][argv…][env…].
    static func arguments(_ pid: pid_t) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return nil }

        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        var index = MemoryLayout<Int32>.size
        // Skip the executable path and the NUL padding after it.
        while index < size && buffer[index] != 0 { index += 1 }
        while index < size && buffer[index] == 0 { index += 1 }

        var args: [String] = []
        var start = index
        while index < size && args.count < Int(argc) {
            if buffer[index] == 0 {
                args.append(String(decoding: buffer[start..<index], as: UTF8.self))
                start = index + 1
            }
            index += 1
        }
        return args
    }

    /// Total CPU time used so far, in seconds.
    static func cpuSeconds(_ pid: pid_t) -> Double? {
        var task = proc_taskinfo()
        let size = Int32(MemoryLayout<proc_taskinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task, size) == size else { return nil }
        let ticks = Double(task.pti_total_user + task.pti_total_system)
        return ticks * timebase / 1_000_000_000
    }

    /// Converts proc_taskinfo times (Mach ticks on Apple silicon) to nanoseconds.
    private static let timebase: Double = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info.denom == 0 ? 1 : Double(info.numer) / Double(info.denom)
    }()

    /// The process's parents, nearest first (stops at launchd).
    static func ancestors(of process: RunningProcess, limit: Int = 8) -> [RunningProcess] {
        var chain: [RunningProcess] = []
        var ppid = process.ppid
        while ppid > 1, chain.count < limit, let parent = info(ppid) {
            chain.append(parent)
            ppid = parent.ppid
        }
        return chain
    }
}
