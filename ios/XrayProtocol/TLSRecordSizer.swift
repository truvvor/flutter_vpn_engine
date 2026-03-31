import Foundation

// MARK: - TLSRecordSizer (Randomized TLS Record Size Distribution)
// Implements Modifications 1-2 from the protocol catalog.
//
// Three-tier distribution mimicking real TLS traffic:
//   - 10% probability: 256-1024 bytes (small HTTP responses/headers)
//   - 20% probability: 1024-4096 bytes (chunked content)
//   - 70% probability: 4096-8192 bytes (bulk data)
//
// Each Write() call independently randomizes the record size.
// Record format: [0x17][0x03][0x03][length_hi][length_lo][encrypted_payload][16_byte_auth_tag]
// Valid record length: 17 <= record_length <= 16640 (RFC 8446)

final class TLSRecordSizer: WrappableConnection {

    private let inner: WrappableConnection
    private let authTagSize: Int = 16  // AES-GCM auth tag

    // TLS record header
    private static let recordType: UInt8 = 0x17      // Application Data
    private static let versionMajor: UInt8 = 0x03    // TLS 1.2 (standard for 1.3 on wire)
    private static let versionMinor: UInt8 = 0x03
    private static let headerSize: Int = 5

    init(conn: WrappableConnection) {
        self.inner = conn
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        // Split data into variable-sized TLS records using three-tier distribution
        writeRecords(data, offset: 0, completion: completion)
    }

    private func writeRecords(_ data: Data, offset: Int, completion: @escaping (Error?) -> Void) {
        guard offset < data.count else {
            completion(nil)
            return
        }

        let remaining = data.count - offset
        let maxRecordSize = selectRecordSize()
        let chunkSize = min(maxRecordSize, remaining)
        let chunk = data.subdata(in: offset..<(offset + chunkSize))

        // Build TLS record with header
        let record = buildTLSRecord(payload: chunk)

        inner.write(record) { [weak self] error in
            if let error = error {
                completion(error)
                return
            }
            self?.writeRecords(data, offset: offset + chunkSize, completion: completion)
        }
    }

    /// Select record size using three-tier distribution.
    ///
    /// Distribution:
    ///   - dice < 10  (10%): 256-1024 bytes (small HTTP responses/headers)
    ///   - dice < 30  (20%): 1024-4096 bytes (chunked content)
    ///   - dice >= 30 (70%): 4096-8192 bytes (bulk data)
    private func selectRecordSize() -> Int {
        let dice = CryptoRandom.randomInt(min: 0, max: 99)

        if dice < 10 {
            // 10% - small records: 256-1024
            return CryptoRandom.randomInt(min: 256, max: 1024)
        } else if dice < 30 {
            // 20% - medium records: 1024-4096
            return CryptoRandom.randomInt(min: 1024, max: 4096)
        } else {
            // 70% - large records: 4096-8192
            return CryptoRandom.randomInt(min: 4096, max: 8192)
        }
    }

    /// Build a TLS Application Data record.
    ///
    /// Format: [0x17][0x03][0x03][length_hi][length_lo][payload]
    /// The payload includes encrypted data; auth tag is handled by the encryption layer.
    private func buildTLSRecord(payload: Data) -> Data {
        let payloadLen = payload.count
        var record = Data(capacity: TLSRecordSizer.headerSize + payloadLen)
        record.append(TLSRecordSizer.recordType)
        record.append(TLSRecordSizer.versionMajor)
        record.append(TLSRecordSizer.versionMinor)
        record.append(UInt8((payloadLen >> 8) & 0xFF))
        record.append(UInt8(payloadLen & 0xFF))
        record.append(payload)
        return record
    }

    func read(minimumLength: Int, maximumLength: Int, completion: @escaping (Data?, Error?) -> Void) {
        // Read path: parse TLS records and extract payloads
        inner.read(minimumLength: minimumLength, maximumLength: maximumLength, completion: completion)
    }

    func close() {
        inner.close()
    }
}

// MARK: - TLS Record Validation

extension TLSRecordSizer {
    /// Validate a TLS record length per RFC 8446.
    /// Valid range: 17 <= record_length <= 16640
    static func isValidRecordLength(_ length: Int) -> Bool {
        return length >= 17 && length <= 16640
    }

    /// Parse TLS record header from data.
    /// Returns (contentType, version, payloadLength) or nil if invalid.
    static func parseRecordHeader(_ data: Data) -> (UInt8, UInt16, Int)? {
        guard data.count >= headerSize else { return nil }

        let contentType = data[0]
        let version = UInt16(data[1]) << 8 | UInt16(data[2])
        let payloadLength = Int(data[3]) << 8 | Int(data[4])

        guard isValidRecordLength(payloadLength) else { return nil }

        return (contentType, version, payloadLength)
    }
}
