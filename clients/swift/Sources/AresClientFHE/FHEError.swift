// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

/// Bridge call failure. `ARES_ERR_CTX_MISMATCH` (-200) maps to `.contextMismatch`.
public enum FHEError: Error, Equatable {
    case contextCreationFailed
    case keygenFailed
    case evalKeyFailed
    case encryptFailed
    case decryptFailed
    case evalFailed
    case serializationFailed
    case deserializeFailed
    case contextMismatch
    case versionUnavailable

    static func fromReturnCode(_ rc: Int32, failure: FHEError) -> FHEError {
        rc == Int32(ARES_ERR_CTX_MISMATCH) ? .contextMismatch : failure
    }
}
