// SPDX-License-Identifier: Apache-2.0
#include <jni.h>
#include <cstdlib>
#include <cstring>
#include <vector>
#include "openfhe_wrapper.h"

static inline jlong H(void* p) { return reinterpret_cast<jlong>(p); }
static inline void* P(jlong h) { return reinterpret_cast<void*>(h); }

// Copy a C array of void* handles out of a Java long[].
static std::vector<void*> handles(JNIEnv* env, jlongArray arr) {
    jsize n = env->GetArrayLength(arr);
    std::vector<void*> out(n);
    jlong* e = env->GetLongArrayElements(arr, nullptr);
    for (jsize i = 0; i < n; i++) out[i] = P(e[i]);
    env->ReleaseLongArrayElements(arr, e, JNI_ABORT);
    return out;
}
// Wrap a malloc'd (uint8_t*,len) into a jbyteArray and free the C buffer.
static jbyteArray bytesAndFree(JNIEnv* env, uint8_t* buf, size_t len, int rc) {
    if (rc != 0 || buf == nullptr) { if (buf) free(buf); return nullptr; }
    jbyteArray out = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(out, 0, (jsize)len, reinterpret_cast<jbyte*>(buf));
    free(buf);
    return out;
}

extern "C" {

// ── version / smoke ──
JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_getVersion(JNIEnv* env, jclass, jbyteArray out) {
    char buf[32] = {0};
    int n = GetOpenFHEVersion(buf, 32);
    if (n > 0) env->SetByteArrayRegion(out, 0, n, reinterpret_cast<jbyte*>(buf));
    return n;
}
JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_smoke(JNIEnv*, jclass) {
    char err[1024] = {0}; return ARESOpenFHESmoke(err, sizeof err);
}

// ── context ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_createContext(JNIEnv*, jclass, jint ringDim, jdouble scale, jint depth) {
    return H(CreateCKKSContext((uint32_t)ringDim, (double)scale, (uint32_t)depth));
}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeContext(JNIEnv*, jclass, jlong c) { FreeCryptoContext(P(c)); }

// ── keygen ── (out-param pairs returned as long[]{pk,sk}; empty array on failure)
JNIEXPORT jlongArray JNICALL Java_ares_client_fhe_NativeFHE_keyGenFirst(JNIEnv* env, jclass, jlong ctx) {
    void* pk=nullptr; void* sk=nullptr;
    int rc = KeyGenFirst(P(ctx), &pk, &sk);
    jlongArray out = env->NewLongArray(rc==0 ? 2 : 0);
    if (rc==0) { jlong v[2]={H(pk),H(sk)}; env->SetLongArrayRegion(out,0,2,v); }
    return out;
}
JNIEXPORT jlongArray JNICALL Java_ares_client_fhe_NativeFHE_keyGenNext(JNIEnv* env, jclass, jlong ctx, jlong prevPk) {
    void* pk=nullptr; void* sk=nullptr;
    int rc = KeyGenNext(P(ctx), P(prevPk), &pk, &sk);
    jlongArray out = env->NewLongArray(rc==0 ? 2 : 0);
    if (rc==0) { jlong v[2]={H(pk),H(sk)}; env->SetLongArrayRegion(out,0,2,v); }
    return out;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_multiAddPublicKeys(JNIEnv* env, jclass, jlong ctx, jlongArray pks) {
    auto v = handles(env, pks); void* out=nullptr;
    int rc = MultiAddPublicKeys(P(ctx), v.data(), (int)v.size(), &out);
    return rc==0 ? H(out) : 0;
}

// ── eval-key shares ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_genEvalMultKeyShare(JNIEnv*, jclass, jlong ctx, jlong sk) {
    void* out=nullptr; return GenEvalMultKeyShare(P(ctx), P(sk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_genRotKeyShare(JNIEnv*, jclass, jlong ctx, jlong sk) {
    void* out=nullptr; return GenRotKeyShare(P(ctx), P(sk), &out)==0 ? H(out) : 0;
}

// ── eval-mult-key 2-round ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMultKeyGenLead(JNIEnv*, jclass, jlong ctx, jlong sk) {
    void* out=nullptr; return EvalMultKeyGenLead(P(ctx), P(sk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMultKeySwitchShare(JNIEnv*, jclass, jlong ctx, jlong sk, jlong base) {
    void* out=nullptr; return EvalMultKeySwitchShare(P(ctx), P(sk), P(base), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_combineEvalMultSwitchShares(JNIEnv* env, jclass, jlong ctx, jlongArray pks, jlongArray shares) {
    auto pv = handles(env, pks); auto sv = handles(env, shares); void* out=nullptr;
    int rc = CombineEvalMultSwitchShares(P(ctx), pv.data(), sv.data(), (int)sv.size(), &out);
    return rc==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMultKeyFinalShare(JNIEnv*, jclass, jlong ctx, jlong sk, jlong joined, jlong finalPk) {
    void* out=nullptr; return EvalMultKeyFinalShare(P(ctx), P(sk), P(joined), P(finalPk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_combineEvalMultFinalShares(JNIEnv* env, jclass, jlong ctx, jlong finalPk, jlongArray shares) {
    auto sv = handles(env, shares); void* out=nullptr;
    int rc = CombineEvalMultFinalShares(P(ctx), P(finalPk), sv.data(), (int)sv.size(), &out);
    return rc==0 ? H(out) : 0;
}
JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_insertEvalMultKey(JNIEnv*, jclass, jlong ctx, jlong key) {
    return InsertEvalMultKey(P(ctx), P(key));
}

// ── eval-sum (rotation) key ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalSumKeyGenLead(JNIEnv*, jclass, jlong ctx, jlong sk) {
    void* out=nullptr; return EvalSumKeyGenLead(P(ctx), P(sk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalSumKeyShare(JNIEnv*, jclass, jlong ctx, jlong sk, jlong base, jlong ownPk) {
    void* out=nullptr; return EvalSumKeyShare(P(ctx), P(sk), P(base), P(ownPk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_combineEvalSumKeys(JNIEnv* env, jclass, jlong ctx, jlongArray pks, jlongArray shares) {
    auto pv = handles(env, pks); auto sv = handles(env, shares); void* out=nullptr;
    int rc = CombineEvalSumKeys(P(ctx), pv.data(), sv.data(), (int)sv.size(), &out);
    return rc==0 ? H(out) : 0;
}
JNIEXPORT jint JNICALL Java_ares_client_fhe_NativeFHE_insertEvalSumKey(JNIEnv*, jclass, jlong ctx, jlong key) {
    return InsertEvalSumKey(P(ctx), P(key));
}

// ── encrypt / decrypt ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_encrypt(JNIEnv* env, jclass, jlong ctx, jlong pk, jdoubleArray values) {
    jsize n = env->GetArrayLength(values);
    jdouble* v = env->GetDoubleArrayElements(values, nullptr);
    void* out = Encrypt(P(ctx), P(pk), v, (int)n);
    env->ReleaseDoubleArrayElements(values, v, JNI_ABORT);
    return H(out);
}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_multiDecMain(JNIEnv*, jclass, jlong ctx, jlong ct, jlong sk) {
    void* out=nullptr; return MultiDecMain(P(ctx), P(ct), P(sk), &out)==0 ? H(out) : 0;
}
JNIEXPORT jdoubleArray JNICALL Java_ares_client_fhe_NativeFHE_multiDecFusion(JNIEnv* env, jclass, jlong ctx, jlongArray partials, jint cap) {
    auto pv = handles(env, partials);
    std::vector<double> out((size_t)cap); int n = cap;
    int rc = MultiDecFusion(P(ctx), pv.data(), (int)pv.size(), out.data(), &n);
    if (rc != 0) return env->NewDoubleArray(0);
    jdoubleArray arr = env->NewDoubleArray(n);
    env->SetDoubleArrayRegion(arr, 0, n, out.data());
    return arr;
}

// ── homomorphic ops ──
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalAdd(JNIEnv*, jclass, jlong c, jlong a, jlong b){return H(EvalAdd(P(c),P(a),P(b)));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalSub(JNIEnv*, jclass, jlong c, jlong a, jlong b){return H(EvalSub(P(c),P(a),P(b)));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMult(JNIEnv*, jclass, jlong c, jlong a, jlong b){return H(EvalMult(P(c),P(a),P(b)));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalMultConst(JNIEnv*, jclass, jlong c, jlong ct, jdouble s){return H(EvalMultConst(P(c),P(ct),s));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalSum(JNIEnv*, jclass, jlong c, jlong ct, jint bs){return H(EvalSum(P(c),P(ct),(int)bs));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalChebyshevSign(JNIEnv*, jclass, jlong c, jlong ct, jint deg){return H(EvalChebyshevSign(P(c),P(ct),(int)deg));}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_evalPolynomial(JNIEnv* env, jclass, jlong c, jlong ct, jdoubleArray coeffs) {
    jsize n = env->GetArrayLength(coeffs); jdouble* v = env->GetDoubleArrayElements(coeffs, nullptr);
    void* out = EvalPolynomial(P(c), P(ct), v, (int)n);
    env->ReleaseDoubleArrayElements(coeffs, v, JNI_ABORT);
    return H(out);
}
JNIEXPORT jlongArray JNICALL Java_ares_client_fhe_NativeFHE_evalArgmax(JNIEnv* env, jclass, jlong c, jlongArray cts, jdoubleArray sharp) {
    auto cv = handles(env, cts);
    jsize sn = env->GetArrayLength(sharp); jdouble* sv = env->GetDoubleArrayElements(sharp, nullptr);
    std::vector<void*> masks(cv.size());
    int rc = EvalArgmax(P(c), (const CiphertextHandle*)cv.data(), (int)cv.size(), sv, (int)sn, masks.data());
    env->ReleaseDoubleArrayElements(sharp, sv, JNI_ABORT);
    if (rc != 0) return env->NewLongArray(0);
    jlongArray out = env->NewLongArray((jsize)masks.size());
    std::vector<jlong> jm(masks.size()); for (size_t i=0;i<masks.size();i++) jm[i]=H(masks[i]);
    env->SetLongArrayRegion(out, 0, (jsize)jm.size(), jm.data());
    return out;
}

// ── serialization ── (serialize → byte[] | null; deserialize → handle | 0)
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeCiphertext(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeCiphertext(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializeCiphertext(JNIEnv* env, jclass, jlong ctx, jbyteArray d){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializeCiphertext(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializePublicKey(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializePublicKey(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializePublicKey(JNIEnv* env, jclass, jlong ctx, jbyteArray d){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializePublicKey(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeSecretKeyShare(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeSecretKeyShare(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializeSecretKeyShare(JNIEnv* env, jclass, jlong ctx, jbyteArray d, jint lead){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializeSecretKeyShare(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n,(int)lead); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeEvalMultKey(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeEvalMultKey(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializeEvalMultKey(JNIEnv* env, jclass, jlong ctx, jbyteArray d){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializeEvalMultKey(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}
JNIEXPORT jbyteArray JNICALL Java_ares_client_fhe_NativeFHE_serializeRotKey(JNIEnv* env, jclass, jlong h){uint8_t* b=nullptr; size_t l=0; int rc=SerializeRotKey(P(h),&b,&l); return bytesAndFree(env,b,l,rc);}
JNIEXPORT jlong JNICALL Java_ares_client_fhe_NativeFHE_deserializeRotKey(JNIEnv* env, jclass, jlong ctx, jbyteArray d){jsize n=env->GetArrayLength(d); jbyte* p=env->GetByteArrayElements(d,nullptr); void* out=DeserializeRotKey(P(ctx),reinterpret_cast<uint8_t*>(p),(size_t)n); env->ReleaseByteArrayElements(d,p,JNI_ABORT); return H(out);}

// ── free ──
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freePublicKey(JNIEnv*, jclass, jlong h){FreePublicKey(P(h));}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeSecretKeyShare(JNIEnv*, jclass, jlong h){FreeSecretKeyShare(P(h));}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeCiphertext(JNIEnv*, jclass, jlong h){FreeCiphertext(P(h));}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeEvalMultKey(JNIEnv*, jclass, jlong h){FreeEvalMultKey(P(h));}
JNIEXPORT void JNICALL Java_ares_client_fhe_NativeFHE_freeRotKey(JNIEnv*, jclass, jlong h){FreeRotKey(P(h));}

} // extern "C"
