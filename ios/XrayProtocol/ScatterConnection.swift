import Foundation

// MARK: - ScatterConnection (TCP Segment Fragmentation)
// Implements Modification 3 from the protocol catalog.
//
// Wraps a connection and splits TLS records across multiple TCP segments
// to break the DPI assumption that TLS records align with TCP segment boundaries.
//
// Wire Format Impact:
//   A single TLS record (e.g., 4096 bytes) is fragmented into multiple TCP packets
//   of 64-512 bytes each, with optional inter-packet jitter of 0-2ms.
//
// Wrapper Order: iOS App -> CommonConn (encryption) -> ScatterConn (TCP frags) -> Wire

final class ScatterConnection: WrappableConnection {

    private let inner: WrappableConnection
    private let minChunk: Int
    private let maxChunk: Int
    private let maxScatter: Int
    private let maxJitterMs: Int
    private var writeCount: Int = 0
    private let lock = NSLock()

    /// Initialize ScatterConnection with configurable parameters.
    ///
    /// - Parameters:
    ///   - conn: The underlying connection to wrap.
    ///   - minChunk: Minimum TCP segment size (default: 64 bytes).
    ///   - maxChunk: Maximum TCP segment size (default: 512 bytes).
    ///   - maxScatter: Scatter only the first N writes, 0 = scatter all (default: 50).
    ///   - maxJitterMs: Maximum micro-jitter between chunks in ms (default: 2).
    init(conn: WrappableConnection, minChunk: Int = 64, maxChunk: Int = 512,
         maxScatter: Int = 50, maxJitterMs: Int = 2) {
        self.inner = conn
        self.minChunk = minChunk
        self.maxChunk = maxChunk
        self.maxScatter = maxScatter
        self.maxJitterMs = maxJitterMs
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        writeCount += 1
        let currentWrite = writeCount
        lock.unlock()

        // After maxScatter writes, pass through without scattering
        if maxScatter > 0 && currentWrite > maxScatter {
            inner.write(data, completion: completion)
            return
        }

        // Don't scatter small writes (less than minChunk * 2)
        if data.count < minChunk * 2 {
            inner.write(data, completion: completion)
            return
        }

        // Fragment into random-sized chunks and send with jitter
        scatterWrite(data, offset: 0, completion: completion)
    }

    private func scatterWrite(_ data: Data, offset: Int, completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        let remaining = data.count - offset
        let chunkSize: Int
        if remaining <= maxChunk {
            chunkSize = remaining
        } else {
            chunkSize = min(CryptoRandom.randomInt(min: minChunk, max: maxChunk), remaining)
        }

        let chunk = data.subdata(in: offset..<(offset + chunkSize))

        inner.write(chunk) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                completion(error)
                return
            }

            let nextOffset = offset + chunkSize
            if nextOffset >= data.count {
                completion(nil)
                return
            }

            // Apply micro-jitter between chunks
            if self.maxJitterMs > 0 {
                let jitterUs = CryptoRandom.randomInt(min: 0, max: self.maxJitterMs * 1000)
                usleep(UInt32(jitterUs))
            }

            self.scatterWrite(data, offset: nextOffset, completion: completion)
        }
    }

    func read(minimumLength: Int, maximumLength: Int, completion: @escaping (Data?, Error?) -> Void) {
        // Read passes through unchanged - TCP reassembly handles incoming fragmentation
        inner.read(minimumLength: minimumLength, maximumLength: maximumLength, completion: completion)
    }

    func close() {
        inner.close()
    }
}
