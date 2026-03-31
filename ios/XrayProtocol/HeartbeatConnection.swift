import Foundation

// MARK: - HeartbeatConnection (Idle Keepalive Packets)
// Implements Modification 4 from the protocol catalog.
//
// Wraps connection and sends fake TLS Application Data records during idle periods
// to prevent DPI from detecting "sleeping tunnels" (connections with no activity
// that behave differently from real browsers).
//
// Record format: [0x17, 0x03, 0x03, payloadLen_hi, payloadLen_lo, random_payload]
//   - 0x17 = TLS 1.3 Application Data type
//   - 0x03 0x03 = TLS 1.2 record version (standard for TLS 1.3 on the wire)
//   - Payload: random 16-128 bytes
//
// Only for non-XTLS (non-XRV) flows with ML-KEM-768 encryption enabled.

final class HeartbeatConnection: WrappableConnection {

    private let inner: WrappableConnection
    private let minIntervalMs: Int
    private let maxIntervalMs: Int
    private let idleThresholdSec: TimeInterval = 2.0

    private var lastActivityTime: Date
    private var heartbeatTimer: DispatchSourceTimer?
    private let timerQueue: DispatchQueue
    private let lock = NSLock()
    private var isClosed = false

    /// Initialize HeartbeatConnection.
    ///
    /// - Parameters:
    ///   - conn: The underlying connection to wrap.
    ///   - minIntervalMs: Minimum interval between heartbeats in ms (default: 5000).
    ///   - maxIntervalMs: Maximum interval between heartbeats in ms (default: 15000).
    init(conn: WrappableConnection, minIntervalMs: Int = 5000, maxIntervalMs: Int = 15000) {
        self.inner = conn
        self.minIntervalMs = minIntervalMs
        self.maxIntervalMs = maxIntervalMs
        self.lastActivityTime = Date()
        self.timerQueue = DispatchQueue(label: "heartbeat.timer.\(UUID().uuidString)")
        startHeartbeatLoop()
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        lastActivityTime = Date()
        lock.unlock()

        inner.write(data, completion: completion)
    }

    func read(minimumLength: Int, maximumLength: Int, completion: @escaping (Data?, Error?) -> Void) {
        inner.read(minimumLength: minimumLength, maximumLength: maximumLength) { [weak self] data, error in
            if data != nil {
                self?.lock.lock()
                self?.lastActivityTime = Date()
                self?.lock.unlock()
            }
            completion(data, error)
        }
    }

    func close() {
        lock.lock()
        isClosed = true
        lock.unlock()

        heartbeatTimer?.cancel()
        heartbeatTimer = nil
        inner.close()
    }

    // MARK: - Heartbeat Logic

    private func startHeartbeatLoop() {
        scheduleNextHeartbeat()
    }

    private func scheduleNextHeartbeat() {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return
        }
        lock.unlock()

        let intervalMs = CryptoRandom.randomInt(min: minIntervalMs, max: maxIntervalMs)
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + .milliseconds(intervalMs))
        timer.setEventHandler { [weak self] in
            self?.sendHeartbeatIfIdle()
        }

        lock.lock()
        heartbeatTimer = timer
        lock.unlock()

        timer.resume()
    }

    private func sendHeartbeatIfIdle() {
        lock.lock()
        guard !isClosed else {
            lock.unlock()
            return
        }
        let idleDuration = Date().timeIntervalSince(lastActivityTime)
        lock.unlock()

        // Only send heartbeat if idle longer than threshold
        if idleDuration >= idleThresholdSec {
            let heartbeat = buildHeartbeatRecord()
            inner.write(heartbeat) { [weak self] _ in
                // Ignore errors for heartbeat writes
                self?.scheduleNextHeartbeat()
            }
        } else {
            scheduleNextHeartbeat()
        }
    }

    /// Build a fake TLS Application Data record.
    ///
    /// Format: [0x17][0x03][0x03][payloadLen_hi][payloadLen_lo][random_payload]
    /// Payload length: random 16-128 bytes
    private func buildHeartbeatRecord() -> Data {
        let payloadLen = CryptoRandom.randomInt(min: 16, max: 128)
        let payload = CryptoRandom.randomBytes(count: payloadLen)

        var record = Data(capacity: 5 + payloadLen)
        record.append(0x17)                             // TLS Application Data type
        record.append(0x03)                             // TLS version major (1.2)
        record.append(0x03)                             // TLS version minor (1.2)
        record.append(UInt8((payloadLen >> 8) & 0xFF))  // Length high byte
        record.append(UInt8(payloadLen & 0xFF))         // Length low byte
        record.append(payload)                          // Random payload

        return record
    }

    deinit {
        heartbeatTimer?.cancel()
    }
}
