import Foundation
import CoreServices

/// Thin wrapper around FSEvents with per-file events.
final class FolderWatcher {
    private var stream: FSEventStreamRef?
    private let paths: [String]
    private let latency: CFTimeInterval
    private let queue = DispatchQueue(label: "agamemnon.fsevents", qos: .utility)
    fileprivate let handler: ([String]) -> Void

    init(paths: [String], latency: CFTimeInterval = 0.5, handler: @escaping ([String]) -> Void) {
        self.paths = paths
        self.latency = latency
        self.handler = handler
    }

    @discardableResult
    func start() -> Bool {
        guard stream == nil, !paths.isEmpty else { return stream != nil }
        var context = FSEventStreamContext(version: 0,
                                           info: Unmanaged.passUnretained(self).toOpaque(),
                                           retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<FolderWatcher>.fromOpaque(info).takeUnretainedValue()
            let array = unsafeBitCast(eventPaths, to: NSArray.self)
            var result: [String] = []
            result.reserveCapacity(count)
            for case let path as String in array { result.append(path) }
            watcher.handler(result)
        }
        let flags = FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents |
                                             kFSEventStreamCreateFlagUseCFTypes |
                                             kFSEventStreamCreateFlagNoDefer)
        guard let s = FSEventStreamCreate(kCFAllocatorDefault, callback, &context,
                                          paths as CFArray,
                                          FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                                          latency, flags) else { return false }
        FSEventStreamSetDispatchQueue(s, queue)
        guard FSEventStreamStart(s) else {
            FSEventStreamInvalidate(s)
            FSEventStreamRelease(s)
            return false
        }
        stream = s
        return true
    }

    func stop() {
        guard let s = stream else { return }
        FSEventStreamStop(s)
        FSEventStreamInvalidate(s)
        FSEventStreamRelease(s)
        stream = nil
    }

    deinit { stop() }
}
