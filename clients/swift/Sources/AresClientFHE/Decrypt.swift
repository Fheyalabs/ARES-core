// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

extension CryptoContext {
    /// Every party (lead and non-lead alike) calls MultiDecMain — matches ThresholdSmokeCKKS.
    public func partialDecrypt(_ ct: Ciphertext, with sk: SecretKeyShare) throws -> Ciphertext {
        var out: UnsafeMutableRawPointer?
        let rc = MultiDecMain(raw, ct.raw, sk.raw, &out)
        guard rc == 0, let out else { throw FHEError.decryptFailed }
        return Ciphertext(out)
    }

    /// Fuse all parties' partials into cleartext slot values.
    public func fuse(_ partials: [Ciphertext], slotCapacity: Int) throws -> [Double] {
        var ptrs: [UnsafeMutableRawPointer?] = partials.map { $0.raw }
        var out = [Double](repeating: 0, count: slotCapacity)
        var n = Int32(slotCapacity)
        let rc = ptrs.withUnsafeMutableBufferPointer { pbuf in
            out.withUnsafeMutableBufferPointer { obuf in
                MultiDecFusion(raw, pbuf.baseAddress, Int32(partials.count), obuf.baseAddress, &n)
            }
        }
        guard rc == 0 else { throw FHEError.decryptFailed }
        return Array(out.prefix(Int(n)))
    }
}
