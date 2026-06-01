// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

extension CryptoContext {

    // MARK: – Eval-mult-key 2-round protocol

    public func evalMultKeyGenLead(_ sk: SecretKeyShare) throws -> EvalMultKey {
        var out: UnsafeMutableRawPointer?
        guard EvalMultKeyGenLead(raw, sk.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return EvalMultKey(out)
    }

    public func evalMultKeySwitchShare(_ sk: SecretKeyShare, base: EvalMultKey) throws -> EvalMultKey {
        var out: UnsafeMutableRawPointer?
        guard EvalMultKeySwitchShare(raw, sk.raw, base.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return EvalMultKey(out)
    }

    public func combineEvalMultSwitchShares(_ pks: [PublicKey], _ shares: [EvalMultKey]) throws -> EvalMultKey {
        var pkPtrs: [UnsafeMutableRawPointer?] = pks.map { $0.raw }
        var shPtrs: [UnsafeMutableRawPointer?] = shares.map { $0.raw }
        var out: UnsafeMutableRawPointer?
        let rc = pkPtrs.withUnsafeMutableBufferPointer { pb in
            shPtrs.withUnsafeMutableBufferPointer { sb in
                CombineEvalMultSwitchShares(raw, pb.baseAddress, sb.baseAddress,
                                           Int32(shares.count), &out)
            }
        }
        guard rc == 0, let out else { throw FHEError.evalKeyFailed }
        return EvalMultKey(out)
    }

    public func evalMultKeyFinalShare(_ sk: SecretKeyShare, joined: EvalMultKey,
                                      finalPK: PublicKey) throws -> EvalMultKey {
        var out: UnsafeMutableRawPointer?
        guard EvalMultKeyFinalShare(raw, sk.raw, joined.raw, finalPK.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return EvalMultKey(out)
    }

    public func combineEvalMultFinalShares(_ finalPK: PublicKey,
                                           _ shares: [EvalMultKey]) throws -> EvalMultKey {
        var shPtrs: [UnsafeMutableRawPointer?] = shares.map { $0.raw }
        var out: UnsafeMutableRawPointer?
        let rc = shPtrs.withUnsafeMutableBufferPointer { sb in
            CombineEvalMultFinalShares(raw, finalPK.raw, sb.baseAddress,
                                      Int32(shares.count), &out)
        }
        guard rc == 0, let out else { throw FHEError.evalKeyFailed }
        return EvalMultKey(out)
    }

    public func insertEvalMultKey(_ key: EvalMultKey) throws {
        guard InsertEvalMultKey(raw, key.raw) == 0 else { throw FHEError.evalKeyFailed }
    }

    // MARK: – Eval-sum (rotation) key protocol

    public func evalSumKeyGenLead(_ sk: SecretKeyShare) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        guard EvalSumKeyGenLead(raw, sk.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return RotKey(out)
    }

    public func evalSumKeyShare(_ sk: SecretKeyShare, base: RotKey,
                                ownPK: PublicKey) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        guard EvalSumKeyShare(raw, sk.raw, base.raw, ownPK.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return RotKey(out)
    }

    public func combineEvalSumKeys(_ pks: [PublicKey], _ shares: [RotKey]) throws -> RotKey {
        var pkPtrs: [UnsafeMutableRawPointer?] = pks.map { $0.raw }
        var shPtrs: [UnsafeMutableRawPointer?] = shares.map { $0.raw }
        var out: UnsafeMutableRawPointer?
        let rc = pkPtrs.withUnsafeMutableBufferPointer { pb in
            shPtrs.withUnsafeMutableBufferPointer { sb in
                CombineEvalSumKeys(raw, pb.baseAddress, sb.baseAddress,
                                   Int32(shares.count), &out)
            }
        }
        guard rc == 0, let out else { throw FHEError.evalKeyFailed }
        return RotKey(out)
    }

    public func insertEvalSumKey(_ key: RotKey) throws {
        guard InsertEvalSumKey(raw, key.raw) == 0 else { throw FHEError.evalKeyFailed }
    }
}
