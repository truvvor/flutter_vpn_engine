import Foundation
import Network
import os.log

// MARK: - Xray Anti-DPI Manager
// Central manager that integrates all anti-DPI protocol modifications
// with the PacketTunnelProvider and VPN connection lifecycle.
//
// This manager is responsible for:
//   1. Creating anti-DPI wrapped connections based on protocol config
//   2. Managing the connection lifecycle (heartbeats, scatter, etc.)
//   3. Applying protocol-level padding (VLESS/VMess headers)
//   4. Applying REALITY-specific modifications (SessionID jitter)

final class XrayAntiDPIManager {

    /// Supported VPN protocol types.
    enum ProtocolType: String {
        case vless = "vless"
        case vmess = "vmess"
        case trojan = "trojan"
    }

    /// Anti-DPI configuration parsed from provider config.
    struct AntiDPIConfig {
        var protocolType: ProtocolType = .vless
        var isXTLS: Bool = false
        var hasMLKEM: Bool = true
        var isReality: Bool = false

        // ScatterConn
        var scatterEnabled: Bool = true
        var scatterMinChunk: Int = 64
        var scatterMaxChunk: Int = 512
        var scatterMaxWrites: Int = 50
        var scatterJitterMs: Int = 2

        // Heartbeat
        var heartbeatEnabled: Bool = true
        var heartbeatMinMs: Int = 5000
        var heartbeatMaxMs: Int = 15000

        // Record sizing
        var recordSizingEnabled: Bool = true

        // Fragmentation
        var fragmentEnabled: Bool = true
        var fragmentLengthMin: Int = 64
        var fragmentLengthMax: Int = 512
        var fragmentDelayMin: Int = 1
        var fragmentDelayMax: Int = 5

        /// Parse from provider configuration dictionary.
        static func from(providerConfig: [String: Any]) -> AntiDPIConfig {
            var config = AntiDPIConfig()

            if let proto = providerConfig["protocol"] as? String {
                config.protocolType = ProtocolType(rawValue: proto) ?? .vless
            }
            if let flow = providerConfig["flow"] as? String {
                config.isXTLS = flow.contains("xtls") || flow.contains("vision")
            }
            if let security = providerConfig["security"] as? String {
                config.isReality = security == "reality"
            }
            if let encryption = providerConfig["encryption"] as? String {
                config.hasMLKEM = encryption != "none"
            }

            // Anti-DPI overrides
            if let antiDPI = providerConfig["antiDPI"] as? [String: Any] {
                config.scatterEnabled = antiDPI["scatterEnabled"] as? Bool ?? true
                config.scatterMinChunk = antiDPI["scatterMinChunk"] as? Int ?? 64
                config.scatterMaxChunk = antiDPI["scatterMaxChunk"] as? Int ?? 512
                config.scatterMaxWrites = antiDPI["scatterMaxWrites"] as? Int ?? 50
                config.scatterJitterMs = antiDPI["scatterJitterMs"] as? Int ?? 2
                config.heartbeatEnabled = antiDPI["heartbeatEnabled"] as? Bool ?? true
                config.heartbeatMinMs = antiDPI["heartbeatMinMs"] as? Int ?? 5000
                config.heartbeatMaxMs = antiDPI["heartbeatMaxMs"] as? Int ?? 15000
                config.recordSizingEnabled = antiDPI["recordSizingEnabled"] as? Bool ?? true
                config.fragmentEnabled = antiDPI["fragmentEnabled"] as? Bool ?? true
                config.fragmentLengthMin = antiDPI["fragmentLengthMin"] as? Int ?? 64
                config.fragmentLengthMax = antiDPI["fragmentLengthMax"] as? Int ?? 512
                config.fragmentDelayMin = antiDPI["fragmentDelayMin"] as? Int ?? 1
                config.fragmentDelayMax = antiDPI["fragmentDelayMax"] as? Int ?? 5
            }

            return config
        }
    }

    private var wrapper: AntiDPIWrapper?
    private var wrappedConnection: WrappableConnection?
    private var antiDPIConfig: AntiDPIConfig

    init(config: AntiDPIConfig = AntiDPIConfig()) {
        self.antiDPIConfig = config
    }

    /// Configure the anti-DPI manager from provider configuration.
    func configure(from providerConfig: [String: Any]) {
        antiDPIConfig = AntiDPIConfig.from(providerConfig: providerConfig)
        wrapper = createWrapper()
        os_log(.info, "XrayAntiDPI: Configured for protocol=%{public}@, xtls=%d, reality=%d, mlkem=%d",
               antiDPIConfig.protocolType.rawValue,
               antiDPIConfig.isXTLS ? 1 : 0,
               antiDPIConfig.isReality ? 1 : 0,
               antiDPIConfig.hasMLKEM ? 1 : 0)
    }

    /// Create an anti-DPI wrapped connection to the VPN server.
    ///
    /// - Parameters:
    ///   - host: Server host.
    ///   - port: Server port.
    ///   - queue: Dispatch queue for connection events.
    ///   - stateHandler: Connection state handler.
    /// - Returns: The wrapped connection, or nil if wrapper is not configured.
    func createWrappedConnection(
        host: String,
        port: UInt16,
        queue: DispatchQueue = .global(),
        stateHandler: @escaping (NWConnection.State) -> Void
    ) -> WrappableConnection? {
        guard let wrapper = wrapper else {
            os_log(.error, "XrayAntiDPI: Wrapper not configured, call configure() first")
            return nil
        }

        let (_, wrapped) = wrapper.createConnection(
            host: host,
            port: port,
            queue: queue,
            stateHandler: stateHandler
        )

        wrappedConnection = wrapped
        os_log(.info, "XrayAntiDPI: Created wrapped connection to %{public}@:%d", host, port)
        return wrapped
    }

    /// Wrap an existing connection with anti-DPI layers.
    func wrapExistingConnection(_ conn: WrappableConnection) -> WrappableConnection {
        guard let wrapper = wrapper else {
            os_log(.error, "XrayAntiDPI: Wrapper not configured, returning unwrapped connection")
            return conn
        }
        let wrapped = wrapper.wrapConnection(conn)
        wrappedConnection = wrapped
        return wrapped
    }

    /// Build a VLESS protocol header with anti-DPI padding.
    func buildProtocolHeader(uuid: Data, command: UInt8, port: UInt16,
                             addressType: UInt8, address: Data) -> Data? {
        guard antiDPIConfig.protocolType == .vless else { return nil }
        return wrapper?.buildVLESSHeader(
            uuid: uuid, command: command, port: port,
            addressType: addressType, address: address
        )
    }

    /// Generate a REALITY SessionID with timestamp jitter.
    func generateJitteredSessionID() -> Data? {
        guard antiDPIConfig.isReality else { return nil }
        return wrapper?.generateSessionID()
    }

    /// Close all connections and cleanup.
    func cleanup() {
        wrappedConnection?.close()
        wrappedConnection = nil
        wrapper = nil
        os_log(.info, "XrayAntiDPI: Cleaned up")
    }

    // MARK: - Private

    private func createWrapper() -> AntiDPIWrapper {
        var wrapperConfig = AntiDPIWrapper.Configuration()

        // ScatterConn
        wrapperConfig.scatterEnabled = antiDPIConfig.scatterEnabled
        wrapperConfig.scatterMinChunk = antiDPIConfig.scatterMinChunk
        wrapperConfig.scatterMaxChunk = antiDPIConfig.scatterMaxChunk
        wrapperConfig.scatterMaxWrites = antiDPIConfig.scatterMaxWrites
        wrapperConfig.scatterMaxJitterMs = antiDPIConfig.scatterJitterMs

        // HeartbeatConn - only for non-XTLS with encryption
        wrapperConfig.heartbeatEnabled = antiDPIConfig.heartbeatEnabled && !antiDPIConfig.isXTLS && antiDPIConfig.hasMLKEM
        wrapperConfig.heartbeatMinIntervalMs = antiDPIConfig.heartbeatMinMs
        wrapperConfig.heartbeatMaxIntervalMs = antiDPIConfig.heartbeatMaxMs

        // Record sizing
        wrapperConfig.recordSizingEnabled = antiDPIConfig.recordSizingEnabled

        // Post-handshake fragmentation
        wrapperConfig.postHandshakeFragEnabled = antiDPIConfig.fragmentEnabled
        if antiDPIConfig.fragmentEnabled {
            var fragConfig = PostHandshakeFragmenter.Config()
            fragConfig.lengthMin = antiDPIConfig.fragmentLengthMin
            fragConfig.lengthMax = antiDPIConfig.fragmentLengthMax
            fragConfig.delayMin = antiDPIConfig.fragmentDelayMin
            fragConfig.delayMax = antiDPIConfig.fragmentDelayMax
            wrapperConfig.fragmentConfig = fragConfig
        }

        // Protocol-level settings
        wrapperConfig.isXTLS = antiDPIConfig.isXTLS
        wrapperConfig.hasEncryption = antiDPIConfig.hasMLKEM
        wrapperConfig.vlessPaddingEnabled = antiDPIConfig.protocolType == .vless && !antiDPIConfig.isXTLS
        wrapperConfig.vmessPaddingEnabled = antiDPIConfig.protocolType == .vmess
        wrapperConfig.sessionIDJitterEnabled = antiDPIConfig.isReality

        return AntiDPIWrapper(config: wrapperConfig)
    }
}
