import Foundation

// MARK: - VLESS Header Padding
// Implements Modification 9 from the protocol catalog.
//
// For non-XRV (non-XTLS Vision) flows, injects random padding into the VLESS
// header addons to vary initial packet size and prevent DPI size-based classification.
//
// Wire Format:
//   [1 byte: padding_length][padding_length bytes: random_data]
//   Padding length: 16-64 bytes
//
// Server ignores unrecognized padding (unmarshal failure = random padding, ignored).

struct VLESSPadding {

    /// Minimum padding size in bytes.
    static let minPaddingLength = 16

    /// Maximum padding size in bytes.
    static let maxPaddingLength = 64

    /// Generate random VLESS header padding.
    ///
    /// Returns Data in format: [1 byte length prefix][random padding bytes]
    /// Total size: 17-65 bytes (1 + 16..64)
    static func generatePadding() -> Data {
        let paddingLen = CryptoRandom.randomInt(min: minPaddingLength, max: maxPaddingLength)
        let padding = CryptoRandom.randomBytes(count: paddingLen)

        var result = Data(capacity: 1 + paddingLen)
        result.append(UInt8(paddingLen))  // 1 byte: padding length
        result.append(padding)            // N bytes: random data
        return result
    }

    /// Inject padding into a VLESS addons buffer.
    ///
    /// - Parameter buffer: Mutable data buffer to append padding to.
    static func injectPadding(into buffer: inout Data) {
        let padding = generatePadding()
        buffer.append(padding)
    }

    /// Build a complete VLESS request header with padding.
    ///
    /// VLESS header structure:
    ///   [1 byte: version][16 bytes: UUID][1 byte: addons_length][addons_payload]
    ///   [1 byte: command][2 bytes: port][1 byte: address_type][address]
    ///
    /// - Parameters:
    ///   - version: VLESS protocol version (typically 0).
    ///   - uuid: 16-byte UUID of the user.
    ///   - command: Command type (1 = TCP, 2 = UDP, 3 = MUX).
    ///   - port: Destination port.
    ///   - addressType: Address type (1 = IPv4, 2 = domain, 3 = IPv6).
    ///   - address: Destination address bytes.
    ///   - flow: Flow type string (empty for non-XTLS).
    ///   - isXTLS: Whether this is an XTLS Vision flow (skips padding if true).
    /// - Returns: Complete VLESS request header with optional padding.
    static func buildRequestHeader(
        version: UInt8 = 0,
        uuid: Data,
        command: UInt8,
        port: UInt16,
        addressType: UInt8,
        address: Data,
        flow: String = "",
        isXTLS: Bool = false
    ) -> Data {
        var header = Data()

        // Version
        header.append(version)

        // UUID (16 bytes)
        header.append(uuid)

        // Addons
        if !isXTLS && flow.isEmpty {
            // Non-XTLS flow: add random padding as addons
            let padding = generatePadding()
            header.append(contentsOf: padding)
        } else {
            // XTLS or flow-based: no padding, zero-length addons
            header.append(0x00)
        }

        // Command
        header.append(command)

        // Port (big-endian)
        header.append(UInt8((port >> 8) & 0xFF))
        header.append(UInt8(port & 0xFF))

        // Address type
        header.append(addressType)

        // Address
        header.append(address)

        return header
    }
}
