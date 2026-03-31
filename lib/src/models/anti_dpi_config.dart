/// Anti-DPI configuration for Xray-core protocol modifications.
///
/// These settings control transport-level obfuscation features that make
/// VPN traffic harder to detect and classify by Deep Packet Inspection systems.
///
/// All modifications are compatible with the modified Xray-core server branch.
class AntiDPIConfig {
  /// Enable TCP segment fragmentation (ScatterConn).
  /// Splits TLS records across multiple TCP segments of 64-512 bytes.
  final bool scatterEnabled;

  /// Minimum TCP segment size for ScatterConn (default: 64).
  final int scatterMinChunk;

  /// Maximum TCP segment size for ScatterConn (default: 512).
  final int scatterMaxChunk;

  /// Number of writes to scatter before passthrough (default: 50, 0 = all).
  final int scatterMaxWrites;

  /// Maximum micro-jitter between scatter chunks in ms (default: 2).
  final int scatterJitterMs;

  /// Enable idle keepalive heartbeat (HeartbeatConn).
  /// Sends fake TLS Application Data records during idle periods.
  /// Only active for non-XTLS flows with ML-KEM-768 encryption.
  final bool heartbeatEnabled;

  /// Minimum heartbeat interval in ms (default: 5000).
  final int heartbeatMinMs;

  /// Maximum heartbeat interval in ms (default: 15000).
  final int heartbeatMaxMs;

  /// Enable three-tier TLS record size randomization.
  /// Distribution: 10% small (256-1024), 20% medium (1024-4096), 70% large (4096-8192).
  final bool recordSizingEnabled;

  /// Enable post-handshake packet fragmentation.
  /// Fragments packets 2-4 after handshake into random chunks with delays.
  final bool fragmentEnabled;

  /// Minimum fragment chunk size (default: 64).
  final int fragmentLengthMin;

  /// Maximum fragment chunk size (default: 512).
  final int fragmentLengthMax;

  /// Minimum inter-fragment delay in ms (default: 1).
  final int fragmentDelayMin;

  /// Maximum inter-fragment delay in ms (default: 5).
  final int fragmentDelayMax;

  const AntiDPIConfig({
    this.scatterEnabled = true,
    this.scatterMinChunk = 64,
    this.scatterMaxChunk = 512,
    this.scatterMaxWrites = 50,
    this.scatterJitterMs = 2,
    this.heartbeatEnabled = true,
    this.heartbeatMinMs = 5000,
    this.heartbeatMaxMs = 15000,
    this.recordSizingEnabled = true,
    this.fragmentEnabled = true,
    this.fragmentLengthMin = 64,
    this.fragmentLengthMax = 512,
    this.fragmentDelayMin = 1,
    this.fragmentDelayMax = 5,
  });

  /// Default configuration with all anti-DPI features enabled.
  static const AntiDPIConfig defaultConfig = AntiDPIConfig();

  /// Minimal configuration (scatter + record sizing only).
  static const AntiDPIConfig minimal = AntiDPIConfig(
    heartbeatEnabled: false,
    fragmentEnabled: false,
  );

  /// Disabled configuration (no anti-DPI).
  static const AntiDPIConfig disabled = AntiDPIConfig(
    scatterEnabled: false,
    heartbeatEnabled: false,
    recordSizingEnabled: false,
    fragmentEnabled: false,
  );

  /// Convert to map for passing to native provider configuration.
  Map<String, dynamic> toMap() {
    return {
      'scatterEnabled': scatterEnabled,
      'scatterMinChunk': scatterMinChunk,
      'scatterMaxChunk': scatterMaxChunk,
      'scatterMaxWrites': scatterMaxWrites,
      'scatterJitterMs': scatterJitterMs,
      'heartbeatEnabled': heartbeatEnabled,
      'heartbeatMinMs': heartbeatMinMs,
      'heartbeatMaxMs': heartbeatMaxMs,
      'recordSizingEnabled': recordSizingEnabled,
      'fragmentEnabled': fragmentEnabled,
      'fragmentLengthMin': fragmentLengthMin,
      'fragmentLengthMax': fragmentLengthMax,
      'fragmentDelayMin': fragmentDelayMin,
      'fragmentDelayMax': fragmentDelayMax,
    };
  }

  /// Create from map (deserialization).
  factory AntiDPIConfig.fromMap(Map<String, dynamic> map) {
    return AntiDPIConfig(
      scatterEnabled: map['scatterEnabled'] as bool? ?? true,
      scatterMinChunk: map['scatterMinChunk'] as int? ?? 64,
      scatterMaxChunk: map['scatterMaxChunk'] as int? ?? 512,
      scatterMaxWrites: map['scatterMaxWrites'] as int? ?? 50,
      scatterJitterMs: map['scatterJitterMs'] as int? ?? 2,
      heartbeatEnabled: map['heartbeatEnabled'] as bool? ?? true,
      heartbeatMinMs: map['heartbeatMinMs'] as int? ?? 5000,
      heartbeatMaxMs: map['heartbeatMaxMs'] as int? ?? 15000,
      recordSizingEnabled: map['recordSizingEnabled'] as bool? ?? true,
      fragmentEnabled: map['fragmentEnabled'] as bool? ?? true,
      fragmentLengthMin: map['fragmentLengthMin'] as int? ?? 64,
      fragmentLengthMax: map['fragmentLengthMax'] as int? ?? 512,
      fragmentDelayMin: map['fragmentDelayMin'] as int? ?? 1,
      fragmentDelayMax: map['fragmentDelayMax'] as int? ?? 5,
    );
  }
}
