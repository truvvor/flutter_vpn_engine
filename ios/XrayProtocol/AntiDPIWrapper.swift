import Foundation
import Network

// MARK: - AntiDPIWrapper
// Combines all anti-DPI protocol modifications into a unified connection wrapper.
//
// Layer stack (from outer to inner):
//   iOS App -> TLSRecordSizer (record sizing) -> HeartbeatConnection (keepalive)
//           -> ScatterConnection (TCP frags) -> Wire
//
// Wrapper order follows the Xray-core architecture:
//   CommonConn (encryption + record sizing) -> ScatterConn (TCP fragmentation) -> Wire
//   ScatterConn MUST wrap the connection BEFORE CommonConn so encrypted records
//   are fragmented, not plaintext.

final class AntiDPIWrapper {

    /// Configuration for anti-DPI connection wrapping.
    struct Configuration {
        // ScatterConn parameters
        var scatterEnabled: Bool = true
        var scatterMinChunk: Int = 64
        var scatterMaxChunk: Int = 512
        var scatterMaxWrites: Int = 50
        var scatterMaxJitterMs: Int = 2

        // HeartbeatConn parameters (only for non-XTLS with ML-KEM-768)
        var heartbeatEnabled: Bool = true
        var heartbeatMinIntervalMs: Int = 5000
        var heartbeatMaxIntervalMs: Int = 15000

        // TLS Record sizing
        var recordSizingEnabled: Bool = true

        // Post-handshake fragmentation
        var postHandshakeFragEnabled: Bool = true
        var fragmentConfig: PostHandshakeFragmenter.Config = .default

        // Protocol-level padding
        var vlessPaddingEnabled: Bool = true
        var vmessPaddingEnabled: Bool = true

        // REALITY-specific
        var sessionIDJitterEnabled: Bool = true

        // Flow type
        var isXTLS: Bool = false
        var hasEncryption: Bool = true  // ML-KEM-768 encryption enabled

        /// Default configuration for VLESS + REALITY with ML-KEM-768.
        static let vlessReality: Configuration = {
            var config = Configuration()
            config.isXTLS = false
            config.hasEncryption = true
            config.sessionIDJitterEnabled = true
            return config
        }()

        /// Configuration for VLESS + XTLS Vision (no heartbeat, no padding).
        static let vlessXTLS: Configuration = {
            var config = Configuration()
            config.isXTLS = true
            config.heartbeatEnabled = false
            config.vlessPaddingEnabled = false
            config.hasEncryption = false
            return config
        }()

        /// Configuration for VMess.
        static let vmess: Configuration = {
            var config = Configuration()
            config.isXTLS = false
            config.hasEncryption = true
            config.vlessPaddingEnabled = false
            config.vmessPaddingEnabled = true
            config.sessionIDJitterEnabled = false
            return config
        }()

        /// Minimal configuration (scatter + record sizing only).
        static let minimal: Configuration = {
            var config = Configuration()
            config.heartbeatEnabled = false
            config.postHandshakeFragEnabled = false
            config.vlessPaddingEnabled = false
            config.vmessPaddingEnabled = false
            config.sessionIDJitterEnabled = false
            return config
        }()
    }

    private let config: Configuration

    init(config: Configuration = .vlessReality) {
        self.config = config
    }

    /// Wrap a connection with all configured anti-DPI layers.
    ///
    /// Layer order (bottom to top):
    ///   1. Base connection (NWConnection or raw socket)
    ///   2. PostHandshakeFragmenter (packets 2-4 fragmentation)
    ///   3. ScatterConnection (TCP segment fragmentation)
    ///   4. TLSRecordSizer (variable record sizes)
    ///   5. HeartbeatConnection (idle keepalive, non-XTLS only)
    ///
    /// - Parameter connection: The base NWConnection to wrap.
    /// - Returns: A WrappableConnection with all anti-DPI layers applied.
    func wrap(connection: NWConnection) -> WrappableConnection {
        return wrapConnection(NWConnectionAdapter(connection))
    }

    /// Wrap a raw socket file descriptor with all configured anti-DPI layers.
    ///
    /// - Parameter fd: The file descriptor of the raw socket.
    /// - Returns: A WrappableConnection with all anti-DPI layers applied.
    func wrap(fd: Int32) -> WrappableConnection {
        return wrapConnection(RawSocketAdapter(fd: fd))
    }

    /// Wrap any WrappableConnection with all configured anti-DPI layers.
    func wrapConnection(_ base: WrappableConnection) -> WrappableConnection {
        var conn: WrappableConnection = base

        // Layer 1: Post-handshake fragmentation (outermost transport layer)
        if config.postHandshakeFragEnabled {
            conn = PostHandshakeFragmenter(conn: conn, config: config.fragmentConfig)
        }

        // Layer 2: ScatterConn (TCP segment fragmentation)
        // Must wrap BEFORE encryption so encrypted records are fragmented
        if config.scatterEnabled {
            conn = ScatterConnection(
                conn: conn,
                minChunk: config.scatterMinChunk,
                maxChunk: config.scatterMaxChunk,
                maxScatter: config.scatterMaxWrites,
                maxJitterMs: config.scatterMaxJitterMs
            )
        }

        // Layer 3: TLS Record sizing (three-tier distribution)
        if config.recordSizingEnabled {
            conn = TLSRecordSizer(conn: conn)
        }

        // Layer 4: HeartbeatConn (idle keepalive) - only for non-XTLS with encryption
        if config.heartbeatEnabled && !config.isXTLS && config.hasEncryption {
            conn = HeartbeatConnection(
                conn: conn,
                minIntervalMs: config.heartbeatMinIntervalMs,
                maxIntervalMs: config.heartbeatMaxIntervalMs
            )
        }

        return conn
    }

    // MARK: - Protocol Header Helpers

    /// Generate a VLESS request header with anti-DPI padding.
    ///
    /// - Parameters:
    ///   - uuid: 16-byte UUID.
    ///   - command: Command type (1 = TCP, 2 = UDP).
    ///   - port: Destination port.
    ///   - addressType: Address type (1 = IPv4, 2 = domain, 3 = IPv6).
    ///   - address: Destination address bytes.
    /// - Returns: VLESS request header with optional padding.
    func buildVLESSHeader(uuid: Data, command: UInt8, port: UInt16,
                          addressType: UInt8, address: Data) -> Data {
        return VLESSPadding.buildRequestHeader(
            uuid: uuid,
            command: command,
            port: port,
            addressType: addressType,
            address: address,
            isXTLS: config.isXTLS
        )
    }

    /// Generate a SessionID with timestamp jitter for REALITY.
    ///
    /// - Returns: 32-byte SessionID with jittered timestamp, or nil if jitter is disabled.
    func generateSessionID() -> Data? {
        guard config.sessionIDJitterEnabled else { return nil }
        return SessionIDJitter.generateSessionID()
    }

    /// Append VMess AEAD padding to a header buffer.
    ///
    /// - Parameter buffer: Mutable VMess AEAD header buffer.
    func appendVMESSPadding(to buffer: inout Data) {
        guard config.vmessPaddingEnabled else { return }
        VMESSPadding.appendPadding(to: &buffer)
    }
}

// MARK: - Connection Factory

extension AntiDPIWrapper {

    /// Create an anti-DPI wrapped TCP connection to the specified endpoint.
    ///
    /// - Parameters:
    ///   - host: The target host.
    ///   - port: The target port.
    ///   - tlsEnabled: Whether to use TLS.
    ///   - queue: Dispatch queue for connection events.
    ///   - stateHandler: Connection state change handler.
    /// - Returns: A tuple of (NWConnection, WrappableConnection).
    func createConnection(
        host: String,
        port: UInt16,
        tlsEnabled: Bool = true,
        queue: DispatchQueue = .global(),
        stateHandler: @escaping (NWConnection.State) -> Void
    ) -> (NWConnection, WrappableConnection) {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port)
        )

        let params = NWParameters.tcp
        if tlsEnabled {
            let tlsOptions = NWProtocolTLS.Options()
            params.defaultProtocolStack.applicationProtocols.insert(tlsOptions, at: 0)
        }

        let connection = NWConnection(to: endpoint, using: params)
        connection.stateUpdateHandler = stateHandler
        connection.start(queue: queue)

        let wrapped = wrap(connection: connection)
        return (connection, wrapped)
    }
}
