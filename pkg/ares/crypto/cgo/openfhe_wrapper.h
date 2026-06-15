// SPDX-License-Identifier: Apache-2.0

#ifndef OPENFHE_WRAPPER_H
#define OPENFHE_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Opaque handle types
typedef void* CryptoContextHandle;
typedef void* PublicKeyHandle;
typedef void* SecretKeyShareHandle;
typedef void* EvalMultKeyHandle;
typedef void* RotKeyHandle;
typedef void* CiphertextHandle;
typedef void* PlaintextHandle;

// Context lifecycle
CryptoContextHandle CreateCKKSContext(
    uint32_t ring_dim,     // 32768
    double scaling_factor, // 2^52
    uint32_t depth         // 12
);
void FreeCryptoContext(CryptoContextHandle ctx);
// SetMinimalRotationKeys opts a context into dimension-parameterized rotation-key
// generation: EvalSumKeyGenLead/Share emit only the at-index keys a profile_dim
// dot-product fold + a payload_slot_count broadcast need, instead of the full ring/2
// batch. Default (unset) keeps full-batch EvalSum + broadcast keygen.
void SetMinimalRotationKeys(CryptoContextHandle ctx, int profile_dim, int payload_slot_count);

// Threshold keygen (N-party)
int KeyGenFirst(CryptoContextHandle ctx,
    PublicKeyHandle* out_pk, SecretKeyShareHandle* out_sk);
int KeyGenNext(CryptoContextHandle ctx, PublicKeyHandle prev_pk,
    PublicKeyHandle* out_pk, SecretKeyShareHandle* out_sk);

// Combine all public keys into joint key
int MultiAddPublicKeys(CryptoContextHandle ctx,
    PublicKeyHandle* pks, int n_keys,
    PublicKeyHandle* out_joint);

// Eval key generation (each party contributes)
int GenEvalMultKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle* out_share);
int GenRotKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle* out_share);

int SingleKeyEvalMultKeyGen(CryptoContextHandle ctx, SecretKeyShareHandle sk);

int EvalMultKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle* out_base);
int EvalMultKeySwitchShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle base, EvalMultKeyHandle* out_share);
int CombineEvalMultSwitchShares(CryptoContextHandle ctx,
    PublicKeyHandle* pks, EvalMultKeyHandle* shares, int n_shares,
    EvalMultKeyHandle* out_joined);
int EvalMultKeyFinalShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle joined, PublicKeyHandle final_pk,
    EvalMultKeyHandle* out_share);
int CombineEvalMultFinalShares(CryptoContextHandle ctx, PublicKeyHandle final_pk,
    EvalMultKeyHandle* shares, int n_shares,
    EvalMultKeyHandle* out_final);
int InsertEvalMultKey(CryptoContextHandle ctx, EvalMultKeyHandle key);

int EvalSumKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle* out_base);
int EvalSumKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk,
    RotKeyHandle* out_share);
// Memory-bounded rotation-key share generation: generates each rotation index's
// share, serializes it, and frees it before the next, so peak RAM is one key
// rather than the whole map. Returns total serialized bytes (shares not retained).
int StreamedRotShareBytes(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk, unsigned long long* out_total_bytes);
// Fully-streamed 2-party rotation keygen: lead base + participant share per index,
// peak bounded to a single rotation index across both parties.
int StreamedTwoPartyRotKeygenBytes(CryptoContextHandle ctx,
    SecretKeyShareHandle sk_lead, SecretKeyShareHandle sk_part, PublicKeyHandle pk_part,
    unsigned long long* out_total_bytes);
// Tests whether 'a' is shared across parties and measures full-key vs b-only
// serialized size, for the CRS wire optimization (transmit only b, rebuild a).
int MeasureBOnlyRotShare(CryptoContextHandle ctx,
    SecretKeyShareHandle sk_lead, SecretKeyShareHandle sk_part, PublicKeyHandle pk_part,
    unsigned long long* out_full_bytes, unsigned long long* out_b_only_bytes, int* out_a_shared);
// Production b-only rotation-key wire (the CRS optimization). The rotation-key
// 'a'-vectors are byte-identical across parties (shared CRS), so a party transmits
// only its 'b'-vectors and the combiner rebuilds the full share from the shared
// 'a' + the party 'b'. No new crypto. out_data is malloc'd; free it in Go.
int SerializeRotKeyBVectors(RotKeyHandle share, uint8_t** out_data, size_t* out_len);
int SerializeRotKeyAVectors(RotKeyHandle share, uint8_t** out_data, size_t* out_len);
RotKeyHandle ReconstructRotKeyFromAB(CryptoContextHandle ctx,
    const uint8_t* a_data, size_t a_len, const uint8_t* b_data, size_t b_len);
int CombineEvalSumKeys(CryptoContextHandle ctx,
    PublicKeyHandle* pks, RotKeyHandle* shares, int n_shares,
    RotKeyHandle* out_final);
// Incremental eval-sum combine: fold shares one at a time (peak RAM = accumulator
// + one share, vs all N for CombineEvalSumKeys). Seed with the lead base, then fold
// each participant share; the result matches CombineEvalSumKeys.
RotKeyHandle EvalSumCombineStart(RotKeyHandle seed);
int EvalSumCombineFold(CryptoContextHandle ctx, RotKeyHandle accum, PublicKeyHandle pk, RotKeyHandle share);
int InsertEvalSumKey(CryptoContextHandle ctx, RotKeyHandle key);

// Encrypt/Decrypt
CiphertextHandle Encrypt(CryptoContextHandle ctx, PublicKeyHandle pk,
    double* values, int n_values);
int DecryptSingle(CryptoContextHandle ctx, CiphertextHandle ct,
    SecretKeyShareHandle sk, double* out_values, int* out_n_values);
int MultiDecMain(CryptoContextHandle ctx, CiphertextHandle ct,
    SecretKeyShareHandle sk, CiphertextHandle* out_partial);
int MultiDecFusion(CryptoContextHandle ctx,
    CiphertextHandle* partials, int n_partials,
    double* out_values, int* out_n_values);

// Homomorphic operations
CiphertextHandle EvalAdd(CryptoContextHandle ctx,
    CiphertextHandle a, CiphertextHandle b);
CiphertextHandle EvalMult(CryptoContextHandle ctx,
    CiphertextHandle a, CiphertextHandle b);
CiphertextHandle EvalSum(CryptoContextHandle ctx,
    CiphertextHandle ct, int batch_size);
CiphertextHandle EvalMultConst(CryptoContextHandle ctx,
    CiphertextHandle ct, double scalar);
CiphertextHandle EvalSub(CryptoContextHandle ctx,
    CiphertextHandle a, CiphertextHandle b);

// Chebyshev sign approximation for argmax
CiphertextHandle EvalChebyshevSign(CryptoContextHandle ctx,
    CiphertextHandle ct, int degree);

// Polynomial evaluation: applies p(x) = sum(coeffs[i] * x^i) slot-wise.
// coeffs is in ascending order (coeffs[0] is the constant term). The
// CryptoContext must have an eval-mult key registered for any
// polynomial with degree >= 2. Returns nullptr on failure.
CiphertextHandle EvalPolynomial(CryptoContextHandle ctx,
    CiphertextHandle ct, double* coeffs, int n_coeffs);

// EvalArgmax: composite argmax over N candidate ciphertexts using a
// caller-supplied sharpening polynomial.
//
// For each i ∈ [0, n_cts): mask[i] = ∏_{j != i} p(cts[i] - cts[j]),
// where p is the polynomial whose coefficients are passed in. The
// polynomial is expected to approximate a step function on
// [-1, 1] — positive inputs → ~1, negative → ~0. For inputs whose
// pairwise differences fall outside [-1, 1] the caller must scale
// them down before calling.
//
// On success returns 0 and writes n_cts new ciphertext handles to
// out_masks (caller frees with FreeCiphertext). On failure returns
// non-zero and out_masks is untouched.
int EvalArgmax(CryptoContextHandle ctx,
    const CiphertextHandle* cts, int n_cts,
    const double* sharp_coeffs, int n_sharp_coeffs,
    CiphertextHandle* out_masks);

// GetOpenFHEVersion writes the linked OpenFHE library version (e.g.
// "v1.5.1") into out_buf. Returns the number of bytes written, or 0
// on failure. out_buf must be at least 32 bytes.
int GetOpenFHEVersion(char* out_buf, int out_cap);

// DeserializeCiphertextErrCtxMismatch is returned via stderr log + a
// nullptr return when the deserialized ciphertext's embedded
// CryptoContext does not match the local ctx. Common cause: OpenFHE
// version skew between the process that serialized and the one
// deserializing.
#define ARES_ERR_CTX_MISMATCH (-200)

// Serialization
int SerializeCiphertext(CiphertextHandle ct, uint8_t** out_data, size_t* out_len);
CiphertextHandle DeserializeCiphertext(CryptoContextHandle ctx,
    uint8_t* data, size_t len);
int SerializePublicKey(PublicKeyHandle pk, uint8_t** out_data, size_t* out_len);
PublicKeyHandle DeserializePublicKey(CryptoContextHandle ctx,
    uint8_t* data, size_t len);
int SerializeSecretKeyShare(SecretKeyShareHandle sk, uint8_t** out_data, size_t* out_len);
SecretKeyShareHandle DeserializeSecretKeyShare(CryptoContextHandle ctx,
    uint8_t* data, size_t len, int lead);
int SerializeEvalMultKey(EvalMultKeyHandle key, uint8_t** out_data, size_t* out_len);
EvalMultKeyHandle DeserializeEvalMultKey(CryptoContextHandle ctx,
    uint8_t* data, size_t len);
int SerializeRotKey(RotKeyHandle key, uint8_t** out_data, size_t* out_len);
RotKeyHandle DeserializeRotKey(CryptoContextHandle ctx,
    uint8_t* data, size_t len);

int ARESFullFusePayloadCKKS(
    uint32_t ring_dim,
    double scaling_factor,
    uint32_t depth,
    const uint8_t* initiator_ct,
    size_t initiator_ct_len,
    const uint8_t* candidate_ct_blob,
    const size_t* candidate_ct_lens,
    const int* candidate_lat_q,
    const int* candidate_lon_q,
    const int* candidate_brownies,
    int n_candidates,
    int profile_dim,
    int initiator_lat_q,
    int initiator_lon_q,
    double alpha,
    double beta,
    double gamma,
    const char* comparator,
    int comparator_degree,
    double comparator_gain,
    double comparator_input_scale,
    double comparator_bound,
    const char* selector_schedule,
    const uint8_t* eval_mult_key,
    size_t eval_mult_key_len,
    const uint8_t* eval_sum_key,
    size_t eval_sum_key_len,
    const int* candidate_packages,
    int package_bytes,
    int payload_slot_count,
    int minimal_rotation_keys,
    uint8_t** out_ct,
    size_t* out_ct_len,
    char* err,
    size_t err_len
);

typedef void* LWEPrivateKeyHandle;

// Scheme-switching argmin (CKKS→FHEW LUT, depth-independent, single-key only).
// Packs num_values keys into slots 0..num_values-1 of a single ciphertext,
// runs EvalMinSchemeSwitching (FHEW-based exact argmin), and returns
// [out_min, out_argmin] as two CKKS ciphertexts. out_argmin is one-hot over
// num_values slots. scale_sign is the scaling factor applied before switching
// to FHEW (default 1.0 if ≤ 0). num_values must be a power of two.
//
// On success returns 0. On failure returns non-zero and writes to err.
int SchemeSwitchingArgmin(
    CryptoContextHandle ctx,
    PublicKeyHandle pk,
    SecretKeyShareHandle sk,
    CiphertextHandle packed_ct,
    uint32_t num_values,
    double scale_sign,
    CiphertextHandle* out_min,
    CiphertextHandle* out_argmin,
    char* err,
    size_t err_len
);

void FreeLWEPrivateKey(LWEPrivateKeyHandle key);

// Memory management
void FreePublicKey(PublicKeyHandle pk);
void FreeSecretKeyShare(SecretKeyShareHandle sk);
void FreeCiphertext(CiphertextHandle ct);
void FreeEvalMultKey(EvalMultKeyHandle key);
void FreeRotKey(RotKeyHandle key);

int ARESOpenFHESmoke(char* err, size_t err_len);

int ARESScoreCandidatesCKKS(
    const double* initiator_profile,
    int profile_dim,
    int initiator_lat_q,
    int initiator_lon_q,
    const double* candidate_profiles,
    const int* candidate_lat_q,
    const int* candidate_lon_q,
    const int* candidate_brownies,
    int n_candidates,
    double alpha,
    double beta,
    double gamma,
    const char* distance_function,
    const char* comparator,
    int comparator_degree,
    double comparator_gain,
    double comparator_input_scale,
    double comparator_bound,
    const char* mask_mode,
    const char* selector_schedule,
    int scaling_mod_size,
    int first_mod_size,
    const int* candidate_packages,
    int package_bytes,
    int payload_slot_count,
    double* out_scores,
    double* out_mask_values,
    double* out_payload_values,
    int* out_winner_index,
    double* out_winner_score,
    char* err,
    size_t err_len
);

#ifdef __cplusplus
}
#endif

#endif // OPENFHE_WRAPPER_H
