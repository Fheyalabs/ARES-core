// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

public final class CryptoContext {
    let raw: UnsafeMutableRawPointer

    public init(ringDim: UInt32, scalingFactor: Double, depth: UInt32) throws {
        guard let h = CreateCKKSContext(ringDim, scalingFactor, depth) else {
            throw FHEError.contextCreationFailed
        }
        self.raw = h
    }
    deinit { FreeCryptoContext(raw) }
}
