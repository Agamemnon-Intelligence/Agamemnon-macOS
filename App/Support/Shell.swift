import Foundation

/// Result of running a command-line tool.
struct ShellResult {
    let status: Int32
    let stdout: String
    let stderr: String
    let timedOut: Bool

    var succeeded: Bool { status == 0 && !timedOut }
}

/// Small helpers for running the system tools Agamemnon relies on
/// (bsdtar, hdiutil, pkgutil, spctl, clamscan, profiles…).
enum Shell {
    private final class Box { var data = Data() }

    /// Runs a tool and waits for it. Output is read on background queues so
    /// large outputs can't dead-lock the pipe.
    @discardableResult
    static func run(_ launchPath: String,
                    _ arguments: [String],
                    timeout: TimeInterval? = nil,
                    stdin: String? = nil,
                    environment: [String: String]? = nil) -> ShellResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        if let environment {
            var env = ProcessInfo.processInfo.environment
            for (k, v) in environment { env[k] = v }
            process.environment = env
        }

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        var inPipe: Pipe?
        if stdin != nil {
            inPipe = Pipe()
            process.standardInput = inPipe
        } else {
            process.standardInput = FileHandle.nullDevice
        }

        do {
            try process.run()
        } catch {
            return ShellResult(status: -1, stdout: "", stderr: error.localizedDescription, timedOut: false)
        }

        if let stdin, let inPipe {
            inPipe.fileHandleForWriting.write(stdin.data(using: .utf8) ?? Data())
            try? inPipe.fileHandleForWriting.close()
        }

        let out = Box()
        let err = Box()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            out.data = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            err.data = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        let timedOut = TimeoutFlag()
        if let timeout {
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                if process.isRunning {
                    timedOut.set()
                    process.terminate()
                }
            }
        }

        process.waitUntilExit()
        group.wait()

        return ShellResult(status: process.terminationStatus,
                           stdout: String(decoding: out.data, as: UTF8.self),
                           stderr: String(decoding: err.data, as: UTF8.self),
                           timedOut: timedOut.value)
    }

    /// Quotes a string for /bin/sh.
    static func quote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Finds an executable in the usual Homebrew / MacPorts / system locations.
    static func which(_ name: String) -> String? {
        let dirs = ["/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/local/sbin",
                    "/opt/local/bin", "/opt/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        for dir in dirs {
            let path = dir + "/" + name
            if FileManager.default.isExecutableFile(atPath: path) { return path }
        }
        return nil
    }
}

/// Thread-safe one-way flag.
final class TimeoutFlag {
    private let lock = NSLock()
    private var flag = false
    func set() { lock.lock(); flag = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
}

/// A long-running process whose output is delivered line by line
/// (used for `clamscan` and `log stream`).
final class LineProcess {
    let process = Process()
    private let outPipe = Pipe()
    private let errPipe = Pipe()
    private var buffer = Data()
    private let finished = DispatchSemaphore(value: 0)
    private var onLine: (String) -> Void

    init(_ launchPath: String, _ arguments: [String], onLine: @escaping (String) -> Void) {
        self.onLine = onLine
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        process.standardOutput = outPipe
        process.standardError = errPipe
        process.standardInput = FileHandle.nullDevice
    }

    /// Collected standard error (read after the process exits).
    private(set) var errorOutput = ""

    private let errLock = NSLock()
    private var errBuffer = Data()

    func start() throws {
        // Drain stderr continuously so a chatty tool can't block on a full pipe.
        errPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self else { return }
            if data.isEmpty { handle.readabilityHandler = nil; return }
            self.errLock.lock()
            self.errBuffer.append(data)
            if self.errBuffer.count > 65_536 { self.errBuffer.removeFirst(self.errBuffer.count - 65_536) }
            self.errLock.unlock()
        }
        outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self else { return }
            if data.isEmpty {
                handle.readabilityHandler = nil
                self.flush(final: true)
                self.finished.signal()
                return
            }
            self.buffer.append(data)
            self.flush(final: false)
        }
        try process.run()
    }

    private func flush(final: Bool) {
        while let newline = buffer.firstIndex(of: 0x0A) {
            let lineData = buffer.subdata(in: buffer.startIndex..<newline)
            buffer.removeSubrange(buffer.startIndex...newline)
            onLine(String(decoding: lineData, as: UTF8.self))
        }
        if final, !buffer.isEmpty {
            onLine(String(decoding: buffer, as: UTF8.self))
            buffer.removeAll()
        }
    }

    /// Waits for the process to exit and for its output to be fully delivered.
    func waitUntilExit() {
        process.waitUntilExit()
        _ = finished.wait(timeout: .now() + 5)
        errLock.lock()
        errorOutput = String(decoding: errBuffer, as: UTF8.self)
        errLock.unlock()
    }

    func terminate() {
        if process.isRunning { process.terminate() }
    }

    var isRunning: Bool { process.isRunning }
}
