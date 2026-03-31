import Foundation

// MARK: - VMess AEAD Random Padding
// Implements Modification 10 from the protocol catalog.
//
// Appends 0-32 bytes of random padding after the VMess AEAD header.
// Server reads by exact lengths (via OpenVMessAEADHeader), so trailing
// padding is safely ignored.
//
// VMess header structure:
//   [16: authID][18: payloadLen_encrypted][8: nonce][payload+tag][0-32: padding]
//
// Server parsing:
//   - Reads exactly 18 bytes for length
//   - Reads exactly 8 bytes for nonce
//   - Reads exact payload length from length field
//   - Does NOT attempt to read padding -> padding is safely ignored

struct VMESSPadding {

    /// Minimum trailing padding size in bytes.
    static let minPaddingLength = 0

    /// Maximum trailing padding size in bytes.
    static let maxPaddingLength = 32

    /// Generate random VMess AEAD trailing padding.
    ///
    /// Returns 0-32 bytes of cryptographically random data.
    static func generatePadding() -> Data {
        let paddingLen = CryptoRandom.randomInt(min: minPaddingLength, max: maxPaddingLength)
        if paddingLen == 0 {
            return Data()
        }
        return CryptoRandom.randomBytes(count: paddingLen)
    }

    /// Append random trailing padding to a VMess AEAD header buffer.
    ///
    /// - Parameter buffer: Mutable data buffer containing the VMess AEAD header.
    static func appendPadding(to buffer: inout Data) {
        let padding = generatePadding()
        if !padding.isEmpty {
            buffer.append(padding)
        }
    }

    // MARK: - VMess AEAD Header Builder

    /// VMess AEAD header components.
    struct AEADHeader {
        let authID: Data         // 16 bytes
        let encryptedLength: Data // 18 bytes (encrypted payload length + tag)
        let nonce: Data          // 8 bytes
        let encryptedPayload: Data // variable length (payload + AEAD tag)
    }

    /// Build a VMess AEAD header with optional trailing padding.
    ///
    /// - Parameter header: The AEAD header components.
    /// - Returns: Complete header data with trailing random padding.
    static func buildHeaderWithPadding(header: AEADHeader) -> Data {
        var buffer = Data()

        // AuthID (16 bytes)
        buffer.append(header.authID)

        // Encrypted payload length (18 bytes)
        buffer.append(header.encryptedLength)

        // Nonce (8 bytes)
        buffer.append(header.nonce)

        // Encrypted payload
        buffer.append(header.encryptedPayload)

        // Trailing random padding (0-32 bytes)
        appendPadding(to: &buffer)

        return buffer
    }
}
