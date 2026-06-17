// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

public final class CryptoContext {
    let raw: UnsafeMutableRawPointer

    public init(ringDim: UInt32, scalingFactor: Double, depth: UInt32,
                batchSize: UInt32 = 0,
                minimalRotationKeys: Bool = false,
                profileDim: Int = 0,
                payloadSlotCount: Int = 0) throws {
        guard let h = CreateCKKSContext(ringDim, scalingFactor, depth, batchSize) else {
            throw FHEError.contextCreationFailed
        }
        self.raw = h
        // Dimension-parameterized rotation keys: generate only the
        // ceil(log2(profileDim)) sum + ceil(log2(payloadSlotCount)) broadcast keys
        // instead of the full ring/2 batch. Load-bearing for fitting 2^16/depth-23
        // multiparty keygen in memory. Default off preserves full-batch behaviour for
        // existing callers (auction / voting / boundcheck).
        if minimalRotationKeys {
            SetMinimalRotationKeys(h, Int32(profileDim), Int32(payloadSlotCount))
        }
    }
    deinit { FreeCryptoContext(raw) }
}
