// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

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
}
