package ares.client.fhe

class CryptoContext(ringDim: Int, scalingFactor: Double, depth: Int) : AutoCloseable {
    internal val raw: Long = NativeFHE.createContext(ringDim, scalingFactor, depth)
        .also { if (it == 0L) throw FHEException("context creation failed") }
    private val state = ContextState(raw)
    @Suppress("unused")
    private val cleanable = FHE_CLEANER.register(this, state)
    private class ContextState(@Volatile var raw: Long) : Runnable {
        override fun run() { val h = raw; if (h != 0L) { raw = 0L; NativeFHE.freeContext(h) } }
    }
    override fun close() { state.run() }

    data class KeyPairShare(val publicKey: PublicKey, val secretKey: SecretKeyShare)

    fun keyGenFirst(): KeyPairShare {
        val a = NativeFHE.keyGenFirst(raw); if (a.size != 2) throw FHEException("keygen first failed")
        return KeyPairShare(PublicKey(a[0]), SecretKeyShare(a[1]))
    }
    fun keyGenNext(prev: PublicKey): KeyPairShare {
        val a = NativeFHE.keyGenNext(raw, prev.raw); if (a.size != 2) throw FHEException("keygen next failed")
        return KeyPairShare(PublicKey(a[0]), SecretKeyShare(a[1]))
    }
    fun multiAddPublicKeys(keys: List<PublicKey>): PublicKey {
        val h = NativeFHE.multiAddPublicKeys(raw, LongArray(keys.size) { keys[it].raw })
        if (h == 0L) throw FHEException("multiAddPublicKeys failed"); return PublicKey(h)
    }

    fun encrypt(values: DoubleArray, under: PublicKey): Ciphertext {
        val h = NativeFHE.encrypt(raw, under.raw, values)
        if (h == 0L) throw FHEException("encrypt failed"); return Ciphertext(h)
    }
    /** Every party uses MultiDecMain (matches ThresholdSmokeCKKS). */
    fun partialDecrypt(ct: Ciphertext, sk: SecretKeyShare): Ciphertext {
        val h = NativeFHE.multiDecMain(raw, ct.raw, sk.raw)
        if (h == 0L) throw FHEException("partial decrypt failed"); return Ciphertext(h)
    }
    fun fuse(partials: List<Ciphertext>, slotCapacity: Int): DoubleArray {
        val out = NativeFHE.multiDecFusion(raw, LongArray(partials.size) { partials[it].raw }, slotCapacity)
        if (out.isEmpty()) throw FHEException("fuse failed"); return out
    }

    // eval-key shares
    fun genEvalMultKeyShare(sk: SecretKeyShare): EvalMultKey { val h = NativeFHE.genEvalMultKeyShare(raw, sk.raw); if (h==0L) throw FHEException("eval-mult share"); return EvalMultKey(h) }
    fun genRotKeyShare(sk: SecretKeyShare): RotKey { val h = NativeFHE.genRotKeyShare(raw, sk.raw); if (h==0L) throw FHEException("rot share"); return RotKey(h) }
    // eval-mult-key 2-round
    fun evalMultKeyGenLead(sk: SecretKeyShare): EvalMultKey { val h = NativeFHE.evalMultKeyGenLead(raw, sk.raw); if (h==0L) throw FHEException("emk lead"); return EvalMultKey(h) }
    fun evalMultKeySwitchShare(sk: SecretKeyShare, base: EvalMultKey): EvalMultKey { val h = NativeFHE.evalMultKeySwitchShare(raw, sk.raw, base.raw); if (h==0L) throw FHEException("emk switch"); return EvalMultKey(h) }
    fun combineEvalMultSwitchShares(pks: List<PublicKey>, shares: List<EvalMultKey>): EvalMultKey {
        require(pks.size >= shares.size)
        val h = NativeFHE.combineEvalMultSwitchShares(raw, LongArray(pks.size){pks[it].raw}, LongArray(shares.size){shares[it].raw})
        if (h==0L) throw FHEException("emk combine1"); return EvalMultKey(h) }
    fun evalMultKeyFinalShare(sk: SecretKeyShare, joined: EvalMultKey, finalPK: PublicKey): EvalMultKey { val h = NativeFHE.evalMultKeyFinalShare(raw, sk.raw, joined.raw, finalPK.raw); if (h==0L) throw FHEException("emk final"); return EvalMultKey(h) }
    fun combineEvalMultFinalShares(finalPK: PublicKey, shares: List<EvalMultKey>): EvalMultKey {
        val h = NativeFHE.combineEvalMultFinalShares(raw, finalPK.raw, LongArray(shares.size){shares[it].raw}); if (h==0L) throw FHEException("emk combine2"); return EvalMultKey(h) }
    fun insertEvalMultKey(key: EvalMultKey) { if (NativeFHE.insertEvalMultKey(raw, key.raw) != 0) throw FHEException("emk insert") }
    // eval-sum (rotation) key
    fun evalSumKeyGenLead(sk: SecretKeyShare): RotKey { val h = NativeFHE.evalSumKeyGenLead(raw, sk.raw); if (h==0L) throw FHEException("esk lead"); return RotKey(h) }
    fun evalSumKeyShare(sk: SecretKeyShare, base: RotKey, ownPK: PublicKey): RotKey { val h = NativeFHE.evalSumKeyShare(raw, sk.raw, base.raw, ownPK.raw); if (h==0L) throw FHEException("esk share"); return RotKey(h) }
    fun combineEvalSumKeys(pks: List<PublicKey>, shares: List<RotKey>): RotKey {
        require(pks.size >= shares.size)
        val h = NativeFHE.combineEvalSumKeys(raw, LongArray(pks.size){pks[it].raw}, LongArray(shares.size){shares[it].raw}); if (h==0L) throw FHEException("esk combine"); return RotKey(h) }
    fun insertEvalSumKey(key: RotKey) { if (NativeFHE.insertEvalSumKey(raw, key.raw) != 0) throw FHEException("esk insert") }
    // homomorphic ops
    fun evalAdd(a: Ciphertext, b: Ciphertext): Ciphertext { val h=NativeFHE.evalAdd(raw,a.raw,b.raw); if(h==0L) throw FHEException("evalAdd"); return Ciphertext(h) }
    fun evalSub(a: Ciphertext, b: Ciphertext): Ciphertext { val h=NativeFHE.evalSub(raw,a.raw,b.raw); if(h==0L) throw FHEException("evalSub"); return Ciphertext(h) }
    fun evalMult(a: Ciphertext, b: Ciphertext): Ciphertext { val h=NativeFHE.evalMult(raw,a.raw,b.raw); if(h==0L) throw FHEException("evalMult"); return Ciphertext(h) }
    fun evalMultConst(ct: Ciphertext, scalar: Double): Ciphertext { val h=NativeFHE.evalMultConst(raw,ct.raw,scalar); if(h==0L) throw FHEException("evalMultConst"); return Ciphertext(h) }
    fun evalSum(ct: Ciphertext, batchSize: Int): Ciphertext { val h=NativeFHE.evalSum(raw,ct.raw,batchSize); if(h==0L) throw FHEException("evalSum"); return Ciphertext(h) }
    fun evalChebyshevSign(ct: Ciphertext, degree: Int): Ciphertext { val h=NativeFHE.evalChebyshevSign(raw,ct.raw,degree); if(h==0L) throw FHEException("cheby"); return Ciphertext(h) }
    fun evalPolynomial(ct: Ciphertext, coefficients: DoubleArray): Ciphertext { val h=NativeFHE.evalPolynomial(raw,ct.raw,coefficients); if(h==0L) throw FHEException("poly"); return Ciphertext(h) }
    fun evalArgmax(cts: List<Ciphertext>, sharpeningCoefficients: DoubleArray): List<Ciphertext> {
        val out = NativeFHE.evalArgmax(raw, LongArray(cts.size){cts[it].raw}, sharpeningCoefficients)
        if (out.size != cts.size) throw FHEException("argmax"); return out.map { Ciphertext(it) } }
    // serialization
    fun serialize(ct: Ciphertext): ByteArray = NativeFHE.serializeCiphertext(ct.raw) ?: throw FHEException("ser ct")
    fun deserializeCiphertext(d: ByteArray): Ciphertext { val h=NativeFHE.deserializeCiphertext(raw,d); if(h==0L) throw FHEException("deser ct"); return Ciphertext(h) }
    fun serialize(pk: PublicKey): ByteArray = NativeFHE.serializePublicKey(pk.raw) ?: throw FHEException("ser pk")
    fun deserializePublicKey(d: ByteArray): PublicKey { val h=NativeFHE.deserializePublicKey(raw,d); if(h==0L) throw FHEException("deser pk"); return PublicKey(h) }
    fun serialize(sk: SecretKeyShare): ByteArray = NativeFHE.serializeSecretKeyShare(sk.raw) ?: throw FHEException("ser sk")
    fun deserializeSecretKeyShare(d: ByteArray, lead: Boolean): SecretKeyShare { val h=NativeFHE.deserializeSecretKeyShare(raw,d,if(lead)1 else 0); if(h==0L) throw FHEException("deser sk"); return SecretKeyShare(h) }
    fun serialize(key: EvalMultKey): ByteArray = NativeFHE.serializeEvalMultKey(key.raw) ?: throw FHEException("ser emk")
    fun deserializeEvalMultKey(d: ByteArray): EvalMultKey { val h=NativeFHE.deserializeEvalMultKey(raw,d); if(h==0L) throw FHEException("deser emk"); return EvalMultKey(h) }
    fun serialize(key: RotKey): ByteArray = NativeFHE.serializeRotKey(key.raw) ?: throw FHEException("ser rk")
    fun deserializeRotKey(d: ByteArray): RotKey { val h=NativeFHE.deserializeRotKey(raw,d); if(h==0L) throw FHEException("deser rk"); return RotKey(h) }
}
