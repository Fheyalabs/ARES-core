// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

extension CryptoContext {
    public func evalAdd(_ a: Ciphertext, _ b: Ciphertext) throws -> Ciphertext {
        guard let h = EvalAdd(raw, a.raw, b.raw) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalSub(_ a: Ciphertext, _ b: Ciphertext) throws -> Ciphertext {
        guard let h = EvalSub(raw, a.raw, b.raw) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalMult(_ a: Ciphertext, _ b: Ciphertext) throws -> Ciphertext {
        guard let h = EvalMult(raw, a.raw, b.raw) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalMultConst(_ ct: Ciphertext, _ scalar: Double) throws -> Ciphertext {
        guard let h = EvalMultConst(raw, ct.raw, scalar) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalSum(_ ct: Ciphertext, batchSize: Int) throws -> Ciphertext {
        guard let h = EvalSum(raw, ct.raw, Int32(batchSize)) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }
}
