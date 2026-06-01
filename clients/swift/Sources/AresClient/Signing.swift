import Foundation
import Crypto

public enum Signing {
    /// Compact, sorted-keys JSON — matches the server's canonicalPayloadFromRawMap.
    public static func canonicalJSON(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object,
                                   options: [.sortedKeys, .withoutEscapingSlashes])
    }

    /// Ed25519 device signature over `label|sessionID|canonical`, the format the
    /// server's verifySignedPayload reconstructs. Returns the raw 64-byte signature.
    public static func deviceSign(deviceKey: Curve25519.Signing.PrivateKey,
                                  label: String, sessionID: String, canonical: Data) throws -> Data {
        var message = Data("\(label)|\(sessionID)|".utf8)
        message.append(canonical)
        return try Data(deviceKey.signature(for: message))
    }
}
