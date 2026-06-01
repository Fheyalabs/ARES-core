// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

public final class PublicKey {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreePublicKey(raw) }
}

public final class SecretKeyShare {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreeSecretKeyShare(raw) }
}

public final class Ciphertext {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreeCiphertext(raw) }
}

public final class EvalMultKey {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreeEvalMultKey(raw) }
}

public final class RotKey {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreeRotKey(raw) }
}
