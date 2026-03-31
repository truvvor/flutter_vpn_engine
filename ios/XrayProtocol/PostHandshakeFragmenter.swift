import Foundation

// MARK: - Post-Handshake Fragmentation (FinalMask)
// Implements Modification 8 from the protocol catalog.
//
// Extended post-handshake fragmentation:
//   - Packet 1 (ClientHello, type 22): original ClientHello fragmentation path
//   - Packets 2-4: fragment into random 64-512 byte chunks with delays
//   - Packets 5+: pass through unchanged
//   - First 10 writes: apply micro-jitter on ALL packets if DelayMax > 0
//
// Breaks the "clean handshake -> immediate data burst" pattern that DPI
// uses to classify VPN tunnels.

final class PostHandshakeFragmenter: WrappableConnection {

    /// Configuration for post-handshake fragmentation.
    struct Config {
        var lengthMin: Int = 64       // Minimum chunk size
        var lengthMax: Int = 512      // Maximum chunk size
        var delayMin: Int = 1         // Minimum inter-chunk delay (ms)
        var delayMax: Int = 5         // Maximum inter-chunk delay (ms)
        var maxSplitMin: Int = 3      // Minimum number of split chunks
        var maxSplitMax: Int = 8      // Maximum number of split chunks
        var packetsFrom: Int = 2      // First packet to fragment
        var packetsTo: Int = 4        // Last packet to fragment

        static let `default` = Config()
    }

    private let inner: WrappableConnection
    private let config: Config
    private var packetCount: Int = 0
    private let lock = NSLock()

    init(conn: WrappableConnection, config: Config = .default) {
        self.inner = conn
        self.config = config
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        packetCount += 1
        let currentPacket = packetCount
        lock.unlock()

        // Packet 1: Check if it's a TLS handshake (ClientHello)
        if currentPacket == 1 && data.count > 5 && data[0] == 22 {
            // TLS handshake record (type 22) - fragment ClientHello
            fragmentClientHello(data, completion: completion)
            return
        }

        // Packets 2-4: fragment generic data packets
        if currentPacket >= config.packetsFrom && currentPacket <= config.packetsTo && data.count > 64 {
            fragmentGeneric(data, completion: completion)
            return
        }

        // First 10 packets: apply micro-jitter even if not fragmenting
        if currentPacket <= 10 && config.delayMax > 0 {
            let microJitterMs = CryptoRandom.randomInt(min: 0, max: config.delayMax / 4)
            if microJitterMs > 0 {
                usleep(UInt32(microJitterMs * 1000))
            }
        }

        // All other packets: pass through
        inner.write(data, completion: completion)
    }

    // MARK: - ClientHello Fragmentation

    /// Fragment a TLS ClientHello record into multiple TCP segments.
    private func fragmentClientHello(_ data: Data, completion: @escaping (Error?) -> Void) {
        fragmentGeneric(data, completion: completion)
    }

    // MARK: - Generic Fragmentation

    /// Fragment data into random-sized chunks with inter-chunk delays.
    ///
    /// Logic:
    ///   for len(p) > 0:
    ///     chunkSize = random(LengthMin..LengthMax)
    ///     maxSplit = random(MaxSplitMin..MaxSplitMax)
    ///     if splitNum >= maxSplit: send remainder
    ///     write chunk
    ///     sleep(random(DelayMin..DelayMax) ms)
    private func fragmentGeneric(_ data: Data, completion: @escaping (Error?) -> Void) {
        let maxSplit = CryptoRandom.randomInt(min: config.maxSplitMin, max: config.maxSplitMax)
        fragmentChunk(data, offset: 0, splitNum: 0, maxSplit: maxSplit, completion: completion)
    }

    private func fragmentChunk(_ data: Data, offset: Int, splitNum: Int, maxSplit: Int,
                                completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        let remaining = data.count - offset
        let chunkEnd: Int

        // If we've reached max splits, send the remainder
        if splitNum >= maxSplit {
            chunkEnd = data.count
        } else {
            let chunkSize = CryptoRandom.randomInt(min: config.lengthMin, max: config.lengthMax)
            chunkEnd = min(offset + chunkSize, data.count)
        }

        let chunk = data.subdata(in: offset..<chunkEnd)

        inner.write(chunk) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                completion(error)
                return
            }

            let nextOffset = chunkEnd
            if nextOffset >= data.count {
                completion(nil)
                return
            }

            // Inter-chunk delay
            let delayMs = CryptoRandom.randomInt(min: self.config.delayMin, max: self.config.delayMax)
            if delayMs > 0 {
                usleep(UInt32(delayMs * 1000))
            }

            self.fragmentChunk(data, offset: nextOffset, splitNum: splitNum + 1,
                               maxSplit: maxSplit, completion: completion)
        }
    }

    func read(minimumLength: Int, maximumLength: Int, completion: @escaping (Data?, Error?) -> Void) {
        // TCP reassembly handles incoming fragmentation automatically
        inner.read(minimumLength: minimumLength, maximumLength: maximumLength, completion: completion)
    }

    func close() {
        inner.close()
    }
}
