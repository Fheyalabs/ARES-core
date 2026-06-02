// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge
import Foundation

// copyAndFree copies the bridge-allocated buffer into a Swift Data value and
// releases the original allocation. Bridge buffers are heap-malloc'd on the
// C side (Go calls C.free on them), so we use the standard libc free here.
// Kept internal (not private) so that Task-6 serializers in this same file
// can reuse it without duplicating the pattern.
func copyAndFree(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int) -> Data {
    guard let ptr else { return Data() }
    defer { free(ptr) }   // bridge buffers are libc-malloc'd (Go frees with C.free)
    guard len > 0 else { return Data() }
    return Data(bytes: ptr, count: len)
}

extension CryptoContext {

    // MARK: – Ciphertext

    public func serialize(_ ct: Ciphertext) throws -> Data {
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard SerializeCiphertext(ct.raw, &buf, &len) == 0 else {
            throw FHEError.serializationFailed
        }
        return copyAndFree(buf, len)
    }

    /// Deserialize a ciphertext under this context. A nil bridge return is reported as
    /// `.deserializeFailed`; a frequent cause is a context/OpenFHE-version mismatch
    /// between the serializer and this context (the bridge logs that case).
    public func deserializeCiphertext(_ data: Data) throws -> Ciphertext {
        var d = data
        let h: UnsafeMutableRawPointer? = d.withUnsafeMutableBytes { raw in
            DeserializeCiphertext(self.raw, raw.bindMemory(to: UInt8.self).baseAddress, data.count)
        }
        guard let h else { throw FHEError.deserializeFailed }
        return Ciphertext(h)
    }

    // MARK: – PublicKey

    public func serialize(_ pk: PublicKey) throws -> Data {
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard SerializePublicKey(pk.raw, &buf, &len) == 0 else {
            throw FHEError.serializationFailed
        }
        return copyAndFree(buf, len)
    }

    public func deserializePublicKey(_ data: Data) throws -> PublicKey {
        var d = data
        let h: UnsafeMutableRawPointer? = d.withUnsafeMutableBytes { raw in
            DeserializePublicKey(self.raw,
                                 raw.bindMemory(to: UInt8.self).baseAddress,
                                 data.count)
        }
        guard let h else { throw FHEError.deserializeFailed }
        return PublicKey(h)
    }

    // MARK: – SecretKeyShare

    public func serialize(_ sk: SecretKeyShare) throws -> Data {
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard SerializeSecretKeyShare(sk.raw, &buf, &len) == 0 else {
            throw FHEError.serializationFailed
        }
        return copyAndFree(buf, len)
    }

    /// Deserialize a secret-key share.
    /// - Parameter lead: `true` if this is the lead (first) party's share.
    public func deserializeSecretKeyShare(_ data: Data, lead: Bool) throws -> SecretKeyShare {
        var d = data
        let h: UnsafeMutableRawPointer? = d.withUnsafeMutableBytes { raw in
            DeserializeSecretKeyShare(self.raw,
                                      raw.bindMemory(to: UInt8.self).baseAddress,
                                      data.count,
                                      lead ? 1 : 0)
        }
        guard let h else { throw FHEError.deserializeFailed }
        return SecretKeyShare(h)
    }

    // MARK: – EvalMultKey

    public func serialize(_ key: EvalMultKey) throws -> Data {
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard SerializeEvalMultKey(key.raw, &buf, &len) == 0 else {
            throw FHEError.serializationFailed
        }
        return copyAndFree(buf, len)
    }

    public func deserializeEvalMultKey(_ data: Data) throws -> EvalMultKey {
        var d = data
        let h: UnsafeMutableRawPointer? = d.withUnsafeMutableBytes { raw in
            DeserializeEvalMultKey(self.raw,
                                   raw.bindMemory(to: UInt8.self).baseAddress,
                                   data.count)
        }
        guard let h else { throw FHEError.deserializeFailed }
        return EvalMultKey(h)
    }

    // MARK: – RotKey

    public func serialize(_ key: RotKey) throws -> Data {
        var buf: UnsafeMutablePointer<UInt8>?
        var len: Int = 0
        guard SerializeRotKey(key.raw, &buf, &len) == 0 else {
            throw FHEError.serializationFailed
        }
        return copyAndFree(buf, len)
    }

    public func deserializeRotKey(_ data: Data) throws -> RotKey {
        var d = data
        let h: UnsafeMutableRawPointer? = d.withUnsafeMutableBytes { raw in
            DeserializeRotKey(self.raw,
                              raw.bindMemory(to: UInt8.self).baseAddress,
                              data.count)
        }
        guard let h else { throw FHEError.deserializeFailed }
        return RotKey(h)
    }
}
