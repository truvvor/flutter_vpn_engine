import Foundation
import Network

// MARK: - Base Connection Protocol

/// Protocol defining a wrappable connection interface for anti-DPI layers.
/// Each layer wraps an underlying connection and modifies write/read behavior.
protocol WrappableConnection: AnyObject {
    func write(_ data: Data, completion: @escaping (Error?) -> Void)
    func read(minimumLength: Int, maximumLength: Int, completion: @escaping (Data?, Error?) -> Void)
    func close()
}

// MARK: - NWConnection Adapter

/// Adapts NWConnection to the WrappableConnection protocol.
final class NWConnectionAdapter: WrappableConnection {
    let connection: NWConnection

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(content: data, completion: .contentProcessed { error in
            completion(error)
        })
    }

    func read(minimumLength: Int, maximumLength: Int, completion: @escaping (Data?, Error?) -> Void) {
        connection.receive(minimumIncompleteLength: minimumLength, maximumLength: maximumLength) { data, _, _, error in
            completion(data, error)
        }
    }

    func close() {
        connection.cancel()
    }
}

// MARK: - Raw Socket Adapter

/// Adapts a raw file descriptor (POSIX socket) to the WrappableConnection protocol.
final class RawSocketAdapter: WrappableConnection {
    let fd: Int32
    private let queue: DispatchQueue

    init(fd: Int32, queue: DispatchQueue = DispatchQueue(label: "rawsocket.io")) {
        self.fd = fd
        self.queue = queue
    }

    func write(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async {
            let result = data.withUnsafeBytes { ptr -> Int in
                guard let base = ptr.baseAddress else { return -1 }
                return Darwin.write(self.fd, base, data.count)
            }
            if result < 0 {
                completion(NSError(domain: "RawSocket", code: Int(errno),
                                   userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))]))
            } else {
                completion(nil)
            }
        }
    }

    func read(minimumLength: Int, maximumLength: Int, completion: @escaping (Data?, Error?) -> Void) {
        queue.async {
            var buffer = [UInt8](repeating: 0, count: maximumLength)
            let bytesRead = Darwin.read(self.fd, &buffer, maximumLength)
            if bytesRead < 0 {
                completion(nil, NSError(domain: "RawSocket", code: Int(errno),
                                        userInfo: [NSLocalizedDescriptionKey: String(cString: strerror(errno))]))
            } else if bytesRead == 0 {
                completion(nil, NSError(domain: "RawSocket", code: -1,
                                        userInfo: [NSLocalizedDescriptionKey: "Connection closed"]))
            } else {
                completion(Data(buffer[0..<bytesRead]), nil)
            }
        }
    }

    func close() {
        Darwin.close(fd)
    }
}

// MARK: - Cryptographic Random Utilities

/// Cryptographically secure random number utilities for anti-DPI operations.
enum CryptoRandom {
    /// Generate a cryptographically secure random integer in range [min, max] (inclusive).
    static func randomInt(min: Int, max: Int) -> Int {
        guard max > min else { return min }
        let range = UInt(max - min + 1)
        var randomValue: UInt64 = 0
        let result = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt64>.size, &randomValue)
        guard result == errSecSuccess else {
            // Fallback to arc4random if SecRandom fails
            return min + Int(arc4random_uniform(UInt32(range)))
        }
        return min + Int(randomValue % UInt64(range))
    }

    /// Generate cryptographically secure random bytes.
    static func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let result = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        if result != errSecSuccess {
            // Fallback
            for i in 0..<count {
                bytes[i] = UInt8(arc4random_uniform(256))
            }
        }
        return Data(bytes)
    }

    /// Generate a random Int64 in range [min, max] (inclusive).
    static func randomInt64(min: Int64, max: Int64) -> Int64 {
        guard max > min else { return min }
        let range = UInt64(max - min + 1)
        var randomValue: UInt64 = 0
        SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt64>.size, &randomValue)
        return min + Int64(randomValue % range)
    }
}
