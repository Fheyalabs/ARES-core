// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge
import Foundation

extension CryptoContext {
    public func encrypt(values: [Double], under pk: PublicKey) throws -> Ciphertext {
        var vals = values
        let h: UnsafeMutableRawPointer? = vals.withUnsafeMutableBufferPointer { buf in
            Encrypt(raw, pk.raw, buf.baseAddress, Int32(buf.count))
        }
        guard let h else { throw FHEError.encryptFailed }
        return Ciphertext(h)
    }

    public func encrypt(intValues: [Int64], under pk: PublicKey) throws -> Ciphertext {
        var vals = intValues
        let h: UnsafeMutableRawPointer? = vals.withUnsafeMutableBufferPointer { buf in
            EncryptPackedInt(raw, pk.raw, buf.baseAddress, Int32(buf.count))
        }
        guard let h else { throw FHEError.encryptFailed }
        return Ciphertext(h)
    }

    /// Encrypt an exact sequence of MSB-first payload chunks. The bridge owns
    /// bit packing so Swift and Kotlin emit identical ciphertext slot layouts.
    public func encryptPayloadChunks(
        payload: Data,
        publicKey: PublicKey,
        chunkSize: Int
    ) throws -> [Data] {
        guard !payload.isEmpty, chunkSize > 0 else { throw FHEError.encryptFailed }
        let (payloadBits, overflow) = payload.count.multipliedReportingOverflow(by: 8)
        guard !overflow, payloadBits % chunkSize == 0 else { throw FHEError.encryptFailed }

        return try stride(from: 0, to: payloadBits, by: chunkSize).map { bitOffset in
            var serialized: UnsafeMutablePointer<UInt8>?
            var serializedLength = 0
            let result = payload.withUnsafeBytes { bytes in
                EncryptSerializedPayloadChunk(
                    raw,
                    publicKey.raw,
                    bytes.bindMemory(to: UInt8.self).baseAddress,
                    payload.count,
                    bitOffset,
                    chunkSize,
                    &serialized,
                    &serializedLength
                )
            }
            guard result == 0, serialized != nil, serializedLength > 0 else {
                if let serialized { free(serialized) }
                throw FHEError.encryptFailed
            }
            return copyAndFree(serialized, serializedLength)
        }
    }
}
