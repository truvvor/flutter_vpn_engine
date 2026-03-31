import Foundation

// MARK: - SessionID Timestamp Jitter (REALITY)
// Implements Modification 7 from the protocol catalog.
//
// Applies +/-300 second jitter to the timestamp embedded in bytes 4-7 of the
// TLS ClientHello SessionID field, preventing DPI from correlating the handshake
// timestamp with real time.
//
// Location in ClientHello:
//   SessionID field starts at byte offset 39 in the TLS handshake record.
//   Bytes 4-7 of the SessionID contain the jittered timestamp (big-endian uint32).
//
// Server does NOT validate the SessionID timestamp, so jitter is safe.

struct SessionIDJitter {

    /// Maximum jitter in seconds (+/-).
    static let maxJitterSeconds: Int64 = 300

    /// Apply timestamp jitter to the SessionID.
    ///
    /// - Parameter sessionID: Mutable 32-byte SessionID data.
    ///   Bytes 4-7 will be overwritten with the jittered timestamp.
    static func applyJitter(to sessionID: inout Data) {
        guard sessionID.count >= 8 else { return }

        let currentTime = Int64(Date().timeIntervalSince1970)
        let jitter = CryptoRandom.randomInt64(min: -maxJitterSeconds, max: maxJitterSeconds)
        let jitteredTime = UInt32(truncatingIfNeeded: currentTime + jitter)

        // Write jittered timestamp to bytes 4-7 (big-endian)
        sessionID[4] = UInt8((jitteredTime >> 24) & 0xFF)
        sessionID[5] = UInt8((jitteredTime >> 16) & 0xFF)
        sessionID[6] = UInt8((jitteredTime >> 8) & 0xFF)
        sessionID[7] = UInt8(jitteredTime & 0xFF)
    }

    /// Generate a complete 32-byte SessionID with jittered timestamp for REALITY.
    ///
    /// Structure:
    ///   - Bytes 0-3: Random data
    ///   - Bytes 4-7: Jittered Unix timestamp (big-endian)
    ///   - Bytes 8-31: Random data (or REALITY-specific fields)
    ///
    /// - Returns: 32-byte SessionID with embedded jittered timestamp.
    static func generateSessionID() -> Data {
        var sessionID = CryptoRandom.randomBytes(count: 32)
        applyJitter(to: &sessionID)
        return sessionID
    }

    /// Modify an existing TLS ClientHello to apply SessionID jitter.
    ///
    /// - Parameter clientHello: Mutable ClientHello data.
    ///   The SessionID starts at offset 39 in a standard TLS 1.3 ClientHello.
    /// - Returns: Whether the modification was applied successfully.
    @discardableResult
    static func applyToClientHello(_ clientHello: inout Data) -> Bool {
        // TLS ClientHello structure:
        //   [1: handshake_type][3: length][2: version][32: random]
        //   [1: session_id_length][0-32: session_id]...
        // session_id_length is at offset 38, session_id starts at 39

        guard clientHello.count > 39 else { return false }

        let sessionIDLength = Int(clientHello[38])
        guard sessionIDLength >= 8 else { return false }
        guard clientHello.count >= 39 + sessionIDLength else { return false }

        // Apply jitter to bytes 4-7 of the SessionID (absolute offset 43-46)
        let currentTime = Int64(Date().timeIntervalSince1970)
        let jitter = CryptoRandom.randomInt64(min: -maxJitterSeconds, max: maxJitterSeconds)
        let jitteredTime = UInt32(truncatingIfNeeded: currentTime + jitter)

        clientHello[43] = UInt8((jitteredTime >> 24) & 0xFF)
        clientHello[44] = UInt8((jitteredTime >> 16) & 0xFF)
        clientHello[45] = UInt8((jitteredTime >> 8) & 0xFF)
        clientHello[46] = UInt8(jitteredTime & 0xFF)

        return true
    }
}
