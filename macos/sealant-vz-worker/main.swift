import Foundation
import Virtualization
import IOKit
import IOKit.pwr_mgt
import Darwin

// MARK: - sealant-vmm-v1 Wire Constants

enum FrameKind: UInt8 {
    case control = 0x01
    case ethFrame = 0x02
    case vsockOpen = 0x03
    case vsockOpenOk = 0x04
    case vsockOpenErr = 0x05
    case vsockData = 0x06
    case vsockFin = 0x07
    case vsockRst = 0x08
}

let frameHeaderLen = 9
let maxEthFrameBytes = 65_600
let maxVsockDataBytes = 256 * 1024
let maxControlFrameBytes = 64 * 1024
let vsockBootPort: UInt32 = 1026
let vsockCapturePort: UInt32 = 1025
let vsockSessionPort: UInt32 = 1027

// MARK: - Launch Spec & Control Messages

struct WorkerLaunchSpec: Decodable {
    let protocolVersion: UInt32
    let vmName: String
    let mode: String
    let vmRoot: String
    let kernelPath: String
    let baseImagePath: String
    let dataImagePath: String
    let cmdline: String
    let vcpus: Int
    let memoryBytes: UInt64
    let mac: String?
    let mtu: Int
    let transportFd: Int32
}

struct RunnerControl: Decodable {
    let type: String
    let bytes: UInt64?
}

// MARK: - Low-level I/O & Symlink-Safe Disk Verification

func readFull(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ len: Int) -> Bool {
    var done = 0
    while done < len {
        let n = Darwin.read(fd, buf.advanced(by: done), len - done)
        if n <= 0 {
            if n < 0 && errno == EINTR { continue }
            return false
        }
        done += n
    }
    return true
}

func writeFull(_ fd: Int32, _ buf: UnsafeRawPointer, _ len: Int) -> Bool {
    var done = 0
    while done < len {
        let n = Darwin.write(fd, buf.advanced(by: done), len - done)
        if n <= 0 {
            if n < 0 && errno == EINTR { continue }
            return false
        }
        done += n
    }
    return true
}

func resolveRealpath(_ path: String) -> String? {
    guard let resolved = Darwin.realpath(path, nil) else { return nil }
    defer { free(resolved) }
    return String(cString: resolved)
}

func verifyAndOpenDisk(path: String, underRoot canonRoot: String, writable: Bool) -> Int32? {
    let parent = (path as NSString).deletingLastPathComponent
    guard let canonParent = resolveRealpath(parent) else {
        fputs("[vz-worker] cannot resolve parent of \(path)\n", stderr)
        return nil
    }
    if canonParent != canonRoot && !canonParent.hasPrefix(canonRoot + "/") {
        fputs("[vz-worker] disk path \(path) escapes vmRoot \(canonRoot)\n", stderr)
        return nil
    }
    let flags: Int32 = O_NOFOLLOW | O_CLOEXEC | (writable ? O_RDWR : O_RDONLY)
    let fd = Darwin.open(path, flags)
    if fd < 0 {
        fputs("[vz-worker] open(\(path)) failed: errno=\(errno)\n", stderr)
        return nil
    }
    var st = stat()
    if fstat(fd, &st) != 0 {
        fputs("[vz-worker] fstat(\(path)) failed: errno=\(errno)\n", stderr)
        Darwin.close(fd)
        return nil
    }
    let isReg = (st.st_mode & S_IFMT) == S_IFREG
    if !isReg || st.st_nlink != 1 || st.st_uid != geteuid() {
        fputs("[vz-worker] disk \(path) failed safety check (reg=\(isReg), nlink=\(st.st_nlink), uid=\(st.st_uid))\n", stderr)
        Darwin.close(fd)
        return nil
    }
    return fd
}

/// Acquires an exclusive non-blocking `flock` on a sibling `.lock` sidecar file instead of
/// `data.img` itself: Apple's `VZDiskImageStorageDeviceAttachment(readOnly: false)` acquires its
/// own internal lock on `data.img` inside the Virtualization XPC helper and fails VM start if
/// another FD already holds `flock(LOCK_EX)` on `data.img`.
func acquireSidecarLock(forDiskPath diskPath: String, underRoot canonRoot: String) -> Int32? {
    let parent = (diskPath as NSString).deletingLastPathComponent
    guard let canonParent = resolveRealpath(parent) else {
        fputs("[vz-worker] cannot resolve parent of \(diskPath)\n", stderr)
        return nil
    }
    if canonParent != canonRoot && !canonParent.hasPrefix(canonRoot + "/") {
        fputs("[vz-worker] lock path for \(diskPath) escapes vmRoot \(canonRoot)\n", stderr)
        return nil
    }
    let lockPath = diskPath + ".lock"
    let fd = Darwin.open(lockPath, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
    if fd < 0 {
        fputs("[vz-worker] open(\(lockPath)) failed: errno=\(errno)\n", stderr)
        return nil
    }
    var st = stat()
    if fstat(fd, &st) != 0 || (st.st_mode & S_IFMT) != S_IFREG || st.st_nlink != 1 || st.st_uid != geteuid() {
        fputs("[vz-worker] sidecar lock \(lockPath) failed safety check\n", stderr)
        Darwin.close(fd)
        return nil
    }
    if flock(fd, LOCK_EX | LOCK_NB) != 0 {
        fputs("[vz-worker] data disk \(diskPath) is already locked by another worker (errno=\(errno))\n", stderr)
        Darwin.close(fd)
        return nil
    }
    return fd
}

func configureTcpKeepalive(_ fd: Int32) {
    var one: Int32 = 1
    _ = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    _ = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, socklen_t(MemoryLayout<Int32>.size))
    var idle: Int32 = 10
    var interval: Int32 = 5
    var count: Int32 = 3
    _ = setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle, socklen_t(MemoryLayout<Int32>.size))
    _ = setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, socklen_t(MemoryLayout<Int32>.size))
    _ = setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, socklen_t(MemoryLayout<Int32>.size))
}

func setSockBuf(_ fd: Int32, _ opt: Int32, _ wanted: Int32) {
    var v = wanted
    _ = setsockopt(fd, SOL_SOCKET, opt, &v, socklen_t(MemoryLayout<Int32>.size))
}

// MARK: - Thread-Safe Frame Writer

final class FrameWriter {
    private let fd: Int32
    private let lock = NSLock()
    private var closed = false

    init(fd: Int32) {
        self.fd = fd
    }

    @discardableResult
    func send(kind: FrameKind, streamId: UInt32, payload: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if closed { return false }
        var hdr = [UInt8](repeating: 0, count: frameHeaderLen)
        hdr[0] = kind.rawValue
        var sidBE = streamId.bigEndian
        var lenBE = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &sidBE) { src in
            for i in 0..<4 { hdr[1 + i] = src[i] }
        }
        withUnsafeBytes(of: &lenBE) { src in
            for i in 0..<4 { hdr[5 + i] = src[i] }
        }
        let hdrOk = hdr.withUnsafeBytes { raw in
            writeFull(fd, raw.baseAddress!, frameHeaderLen)
        }
        if !hdrOk {
            closed = true
            return false
        }
        if !payload.isEmpty {
            let bodyOk = payload.withUnsafeBytes { raw in
                writeFull(fd, raw.baseAddress!, payload.count)
            }
            if !bodyOk {
                closed = true
                return false
            }
        }
        return true
    }

    @discardableResult
    func sendControl(_ obj: [String: Any]) -> Bool {
        guard let data = try? JSONSerialization.data(withJSONObject: obj) else { return false }
        return send(kind: .control, streamId: 0, payload: data)
    }

    func shutdown() {
        lock.lock()
        closed = true
        lock.unlock()
        Darwin.shutdown(fd, SHUT_RDWR)
    }
}

// MARK: - Active Vsock Stream Table (Retains VZVirtioSocketConnection for FD Lifetime)

final class StreamTable {
    private let lock = NSLock()
    private var streams: [UInt32: VZVirtioSocketConnection] = [:]
    private var nextEvenStreamId: UInt32 = 2

    func allocateEvenId() -> UInt32 {
        lock.lock()
        defer { lock.unlock() }
        let id = nextEvenStreamId
        nextEvenStreamId &+= 2
        if nextEvenStreamId == 0 { nextEvenStreamId = 2 }
        return id
    }

    func insert(id: UInt32, connection: VZVirtioSocketConnection) {
        lock.lock()
        streams[id] = connection
        lock.unlock()
    }

    func get(id: UInt32) -> VZVirtioSocketConnection? {
        lock.lock()
        defer { lock.unlock() }
        return streams[id]
    }

    func remove(id: UInt32) -> VZVirtioSocketConnection? {
        lock.lock()
        defer { lock.unlock() }
        return streams.removeValue(forKey: id)
    }
}

// MARK: - VZ Worker Runtime

final class WorkerController: NSObject, VZVirtualMachineDelegate, VZVirtioSocketListenerDelegate {
    let spec: WorkerLaunchSpec
    let writer: FrameWriter
    let streams = StreamTable()
    let vmQueue = DispatchQueue(label: "sh.sealant.vz-worker.vm")
    var vm: VZVirtualMachine!
    var sockDev: VZVirtioSocketDevice?
    var balloon: VZVirtioTraditionalMemoryBalloonDevice?
    var bootAccepted = false
    var maxMemoryBytes: UInt64 = 0
    var minMemoryBytes: UInt64 = 0
    var dgramFd: Int32 = -1
    var powerPort: IONotificationPortRef?
    var powerNotifier: io_object_t = 0
    var rootPowerDomain: io_connect_t = 0
    var memoryPressureSource: DispatchSourceMemoryPressure?
    var stopping = false

    init(spec: WorkerLaunchSpec, writer: FrameWriter) {
        self.spec = spec
        self.writer = writer
        super.init()
    }

    func startPumpForVsock(streamId: UInt32, connection: VZVirtioSocketConnection) {
        let fd = connection.fileDescriptor
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var buf = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let n = buf.withUnsafeMutableBytes { raw in
                    Darwin.read(fd, raw.baseAddress!, raw.count)
                }
                if n > 0 {
                    let data = Data(buf[0..<n])
                    if !self.writer.send(kind: .vsockData, streamId: streamId, payload: data) {
                        break
                    }
                } else if n == 0 {
                    _ = self.writer.send(kind: .vsockFin, streamId: streamId, payload: Data())
                    break
                } else {
                    if errno == EINTR { continue }
                    _ = self.writer.send(kind: .vsockRst, streamId: streamId, payload: Data())
                    break
                }
            }
            // Wait slightly or drop only when peer also closes; releasing connection closes FD.
            _ = self.streams.remove(id: streamId)
        }
    }

    // MARK: VZVirtioSocketListenerDelegate

    func listener(
        _ listener: VZVirtioSocketListener,
        shouldAcceptNewConnection connection: VZVirtioSocketConnection,
        from socketDevice: VZVirtioSocketDevice
    ) -> Bool {
        let port = connection.destinationPort
        if port == vsockBootPort {
            if bootAccepted {
                return false
            }
            bootAccepted = true
            // Enforce single-use vsock:1026 immediately so guest root cannot redial after boot.
            socketDevice.removeSocketListener(forPort: vsockBootPort)
        } else if port == vsockSessionPort && spec.mode != "normal" {
            return false
        }

        let streamId = streams.allocateEvenId()
        streams.insert(id: streamId, connection: connection)
        var portBE = port.bigEndian
        let payload = Data(bytes: &portBE, count: 4)
        _ = writer.send(kind: .vsockOpen, streamId: streamId, payload: payload)
        startPumpForVsock(streamId: streamId, connection: connection)
        return true
    }

    // MARK: VZVirtualMachineDelegate

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        _ = writer.sendControl(["type": "vmExited", "clean": true])
        writer.shutdown()
        exit(0)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        _ = writer.sendControl([
            "type": "vmExited",
            "clean": false,
            "error": error.localizedDescription,
        ])
        writer.shutdown()
        exit(1)
    }

    // MARK: Host Wake & Memory Pressure

    func installPowerWakeObserver() {
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()
        let callback: IOServiceInterestCallback = { refCon, _, messageType, messageArgument in
            guard let refCon else { return }
            let ctrl = Unmanaged<WorkerController>.fromOpaque(refCon).takeUnretainedValue()
            // kIOMessageCanSystemSleep = 0xe0000270, kIOMessageSystemWillSleep = 0xe0000280,
            // kIOMessageSystemHasPoweredOn = 0xe0000300
            let kCanSleep: UInt32 = 0xe0000270
            let kWillSleep: UInt32 = 0xe0000280
            let kHasPoweredOn: UInt32 = 0xe0000300
            if messageType == kCanSleep || messageType == kWillSleep {
                IOAllowPowerChange(ctrl.rootPowerDomain, Int(bitPattern: messageArgument))
            } else if messageType == kHasPoweredOn {
                let ns = UInt64(Date().timeIntervalSince1970 * 1_000_000_000.0)
                _ = ctrl.writer.sendControl(["type": "hostWake", "utcEpochNs": ns])
            }
        }
        rootPowerDomain = IORegisterForSystemPower(selfPtr, &powerPort, callback, &powerNotifier)
        if rootPowerDomain != 0, let port = powerPort {
            IONotificationPortSetDispatchQueue(port, DispatchQueue.global(qos: .utility))
        }
    }

    func installMemoryPressureObserver() {
        let src = DispatchSource.makeMemoryPressureSource(
            eventMask: [.normal, .warning, .critical],
            queue: DispatchQueue.global(qos: .utility)
        )
        src.setEventHandler { [weak self] in
            guard let self else { return }
            let event = src.data
            let level: String
            if event.contains(.critical) {
                level = "critical"
            } else if event.contains(.warning) {
                level = "warning"
            } else {
                level = "normal"
            }
            _ = self.writer.sendControl(["type": "memoryPressure", "level": level])
        }
        src.resume()
        self.memoryPressureSource = src
    }

    // MARK: Runner -> Worker Frame Reader

    func startTransportReader() {
        let fd = spec.transportFd
        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            guard let self else { return }
            let hdrBuf = UnsafeMutableRawPointer.allocate(byteCount: frameHeaderLen, alignment: 8)
            let payloadBuf = UnsafeMutableRawPointer.allocate(byteCount: maxVsockDataBytes, alignment: 8)
            defer {
                hdrBuf.deallocate()
                payloadBuf.deallocate()
            }

            while true {
                if !readFull(fd, hdrBuf, frameHeaderLen) {
                    // Runner TCP link closed (docker stop/kill or Docker Desktop restart):
                    // stop VM cleanly so no orphaned macOS VM ever lingers.
                    self.stopOnTransportEof()
                    return
                }
                let kindRaw = hdrBuf.load(fromByteOffset: 0, as: UInt8.self)
                let streamId = UInt32(bigEndian: hdrBuf.loadUnaligned(fromByteOffset: 1, as: UInt32.self))
                let length = Int(UInt32(bigEndian: hdrBuf.loadUnaligned(fromByteOffset: 5, as: UInt32.self)))
                if length > maxVsockDataBytes {
                    self.stopOnTransportEof()
                    return
                }
                if length > 0 && !readFull(fd, payloadBuf, length) {
                    self.stopOnTransportEof()
                    return
                }
                guard let kind = FrameKind(rawValue: kindRaw) else {
                    self.stopOnTransportEof()
                    return
                }
                switch kind {
                case .control:
                    let data = Data(bytes: payloadBuf, count: length)
                    self.handleRunnerControl(data)
                case .ethFrame:
                    if self.dgramFd >= 0 && length > 0 && length <= maxEthFrameBytes {
                        var retries = 0
                        while true {
                            let n = Darwin.write(self.dgramFd, payloadBuf, length)
                            if n >= 0 { break }
                            if errno == ENOBUFS && retries < 200 {
                                retries += 1
                                usleep(100)
                                continue
                            }
                            break
                        }
                    }
                case .vsockOpen:
                    if length == 4 {
                        let port = UInt32(bigEndian: payloadBuf.loadUnaligned(fromByteOffset: 0, as: UInt32.self))
                        self.handleRunnerVsockOpen(streamId: streamId, port: port)
                    }
                case .vsockOpenOk:
                    break
                case .vsockOpenErr:
                    _ = self.streams.remove(id: streamId)
                case .vsockData:
                    if let conn = self.streams.get(id: streamId), length > 0 {
                        if !writeFull(conn.fileDescriptor, payloadBuf, length) {
                            _ = self.streams.remove(id: streamId)
                            _ = self.writer.send(kind: .vsockRst, streamId: streamId, payload: Data())
                        }
                    }
                case .vsockFin:
                    if let conn = self.streams.get(id: streamId) {
                        Darwin.shutdown(conn.fileDescriptor, SHUT_WR)
                    }
                case .vsockRst:
                    _ = self.streams.remove(id: streamId)
                }
            }
        }
    }

    func handleRunnerVsockOpen(streamId: UInt32, port: UInt32) {
        vmQueue.async { [weak self] in
            guard let self, let dev = self.sockDev else {
                _ = self?.writer.send(kind: .vsockOpenErr, streamId: streamId, payload: Data("no vsock device".utf8))
                return
            }
            dev.connect(toPort: port) { result in
                switch result {
                case .success(let conn):
                    self.streams.insert(id: streamId, connection: conn)
                    _ = self.writer.send(kind: .vsockOpenOk, streamId: streamId, payload: Data())
                    self.startPumpForVsock(streamId: streamId, connection: conn)
                case .failure(let err):
                    _ = self.writer.send(
                        kind: .vsockOpenErr,
                        streamId: streamId,
                        payload: Data(err.localizedDescription.utf8)
                    )
                }
            }
        }
    }

    func handleRunnerControl(_ data: Data) {
        guard let cmd = try? JSONDecoder().decode(RunnerControl.self, from: data) else { return }
        switch cmd.type {
        case "requestStop":
            vmQueue.async { [weak self] in
                guard let self else { return }
                if self.vm.canRequestStop {
                    try? self.vm.requestStop()
                }
            }
        case "forceKill":
            vmQueue.async { [weak self] in
                guard let self else { return }
                self.vm.stop { _ in
                    _ = self.writer.sendControl(["type": "vmExited", "clean": false, "error": "force killed"])
                    self.writer.shutdown()
                    exit(0)
                }
            }
        case "setBalloonTarget":
            guard let requested = cmd.bytes else { return }
            let aligned = (requested / (1024 * 1024)) * (1024 * 1024)
            let clamped = max(minMemoryBytes, min(maxMemoryBytes, aligned))
            vmQueue.async { [weak self] in
                self?.balloon?.targetVirtualMachineMemorySize = clamped
            }
        case "ping":
            _ = writer.sendControl(["type": "pong"])
        default:
            break
        }
    }

    func stopOnTransportEof() {
        vmQueue.async { [weak self] in
            guard let self, !self.stopping else { return }
            self.stopping = true
            if self.vm.canRequestStop {
                try? self.vm.requestStop()
            }
            self.vmQueue.asyncAfter(deadline: .now() + 5) {
                self.vm.stop { _ in exit(0) }
            }
        }
    }
}

// MARK: - Main Entry

signal(SIGPIPE, SIG_IGN)
_ = setsid()

let stdinData = FileHandle.standardInput.readDataToEndOfFile()
guard let spec = try? JSONDecoder().decode(WorkerLaunchSpec.self, from: stdinData) else {
    fputs("[vz-worker] failed to decode WorkerLaunchSpec JSON from stdin\n", stderr)
    exit(2)
}
guard spec.protocolVersion == 1 else {
    fputs("[vz-worker] unsupported protocolVersion \(spec.protocolVersion)\n", stderr)
    exit(2)
}
guard let canonRoot = resolveRealpath(spec.vmRoot) else {
    fputs("[vz-worker] cannot resolve vmRoot \(spec.vmRoot)\n", stderr)
    exit(2)
}

// Validate both disks (symlink-safe + regular + nlink == 1 + owned by UID) and hold an exclusive
// sidecar flock beside data.img for the worker's entire lifetime (so VZ can hold its own lock on
// data.img itself).
guard let baseCheckFd = verifyAndOpenDisk(path: spec.baseImagePath, underRoot: canonRoot, writable: false) else {
    exit(3)
}
Darwin.close(baseCheckFd)

guard let dataCheckFd = verifyAndOpenDisk(path: spec.dataImagePath, underRoot: canonRoot, writable: true) else {
    exit(4)
}
Darwin.close(dataCheckFd)

guard let sidecarLockFd = acquireSidecarLock(forDiskPath: spec.dataImagePath, underRoot: canonRoot) else {
    exit(4)
}
// Intentionally kept open (and locked!) for the lifetime of sealant-vz-worker.
_ = sidecarLockFd

configureTcpKeepalive(spec.transportFd)
let writer = FrameWriter(fd: spec.transportFd)
let controller = WorkerController(spec: spec, writer: writer)

let config = VZVirtualMachineConfiguration()
config.platform = VZGenericPlatformConfiguration()
config.cpuCount = max(
    VZVirtualMachineConfiguration.minimumAllowedCPUCount,
    min(spec.vcpus, VZVirtualMachineConfiguration.maximumAllowedCPUCount)
)
let clampedMem = max(
    VZVirtualMachineConfiguration.minimumAllowedMemorySize,
    min(spec.memoryBytes, VZVirtualMachineConfiguration.maximumAllowedMemorySize)
)
config.memorySize = clampedMem
controller.maxMemoryBytes = clampedMem
controller.minMemoryBytes = max(VZVirtualMachineConfiguration.minimumAllowedMemorySize, 512 * 1024 * 1024)

let bootLoader = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: spec.kernelPath))
bootLoader.commandLine = spec.cmdline
config.bootLoader = bootLoader

do {
    let vda = try VZDiskImageStorageDeviceAttachment(
        url: URL(fileURLWithPath: spec.baseImagePath),
        readOnly: true,
        cachingMode: .cached,
        synchronizationMode: .none
    )
    // Use .full (F_FULLFSYNC) on vdb so guest sync()/fsync() is durable across macOS power loss.
    let vdb = try VZDiskImageStorageDeviceAttachment(
        url: URL(fileURLWithPath: spec.dataImagePath),
        readOnly: false,
        cachingMode: .cached,
        synchronizationMode: .full
    )
    config.storageDevices = [
        VZVirtioBlockDeviceConfiguration(attachment: vda),
        VZVirtioBlockDeviceConfiguration(attachment: vdb),
    ]
} catch {
    fputs("[vz-worker] disk attachment failed: \(error)\n", stderr)
    exit(5)
}

var negotiatedMtu = spec.mtu
if spec.mode == "normal" {
    var sp: [Int32] = [-1, -1]
    guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sp) == 0 else {
        fputs("[vz-worker] socketpair failed: errno=\(errno)\n", stderr)
        exit(6)
    }
    setSockBuf(sp[0], SO_SNDBUF, 2 * 1024 * 1024)
    setSockBuf(sp[0], SO_RCVBUF, 4 * 1024 * 1024)
    setSockBuf(sp[1], SO_SNDBUF, 2 * 1024 * 1024)
    setSockBuf(sp[1], SO_RCVBUF, 4 * 1024 * 1024)
    controller.dgramFd = sp[1]

    let netAttachment = VZFileHandleNetworkDeviceAttachment(
        fileHandle: FileHandle(fileDescriptor: sp[0], closeOnDealloc: true)
    )
    netAttachment.maximumTransmissionUnit = spec.mtu
    negotiatedMtu = netAttachment.maximumTransmissionUnit

    let netDevice = VZVirtioNetworkDeviceConfiguration()
    netDevice.attachment = netAttachment
    if let macStr = spec.mac, let vzMac = VZMACAddress(string: macStr) {
        netDevice.macAddress = vzMac
    }
    config.networkDevices = [netDevice]

    // Pump guest -> runner raw Ethernet frames
    let dgramFd = sp[1]
    DispatchQueue.global(qos: .userInteractive).async {
        var buf = [UInt8](repeating: 0, count: maxEthFrameBytes)
        while true {
            let n = buf.withUnsafeMutableBytes { raw in
                Darwin.read(dgramFd, raw.baseAddress!, raw.count)
            }
            if n <= 0 {
                if n < 0 && errno == EINTR { continue }
                break
            }
            let frame = Data(buf[0..<n])
            if !writer.send(kind: .ethFrame, streamId: 0, payload: frame) {
                break
            }
        }
    }
} else {
    // Recovery mode: zero network devices!
    config.networkDevices = []
}

config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
config.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]

// Gate 0 catch: fileHandleForReading MUST be nil (FileHandle.nullDevice throws NSInvalidArgumentException).
let serialPipe = Pipe()
let serialAttachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: nil,
    fileHandleForWriting: serialPipe.fileHandleForWriting
)
let console = VZVirtioConsoleDeviceSerialPortConfiguration()
console.attachment = serialAttachment
config.serialPorts = [console]

serialPipe.fileHandleForReading.readabilityHandler = { fh in
    let data = fh.availableData
    if !data.isEmpty, let text = String(data: data, encoding: .utf8) {
        _ = writer.sendControl(["type": "console", "data": text])
    }
}

do {
    try config.validate()
} catch {
    fputs("[vz-worker] config.validate() failed: \(error)\n", stderr)
    exit(7)
}

let vm = VZVirtualMachine(configuration: config, queue: controller.vmQueue)
controller.vm = vm
vm.delegate = controller

let bootListener = VZVirtioSocketListener()
bootListener.delegate = controller
let captureListener = VZVirtioSocketListener()
captureListener.delegate = controller
let sessionListener = VZVirtioSocketListener()
sessionListener.delegate = controller

controller.installPowerWakeObserver()
controller.installMemoryPressureObserver()
controller.startTransportReader()

controller.vmQueue.async {
    if let sockDev = vm.socketDevices.first as? VZVirtioSocketDevice {
        controller.sockDev = sockDev
        sockDev.setSocketListener(bootListener, forPort: vsockBootPort)
        sockDev.setSocketListener(captureListener, forPort: vsockCapturePort)
        if spec.mode == "normal" {
            sockDev.setSocketListener(sessionListener, forPort: vsockSessionPort)
        }
    }
    if let balloon = vm.memoryBalloonDevices.first as? VZVirtioTraditionalMemoryBalloonDevice {
        controller.balloon = balloon
    }
    vm.start { result in
        switch result {
        case .success:
            let nowMs = UInt64(Date().timeIntervalSince1970 * 1000.0)
            _ = writer.sendControl([
                "type": "vmStarted",
                "bootTimeUtcMs": nowMs,
                "negotiatedMtu": negotiatedMtu,
            ])
        case .failure(let err):
            _ = writer.sendControl([
                "type": "vmExited",
                "clean": false,
                "error": "VM start failed: \(err.localizedDescription)",
            ])
            writer.shutdown()
            exit(8)
        }
    }
}

RunLoop.main.run()
