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
int CombineEvalSumKeys(CryptoContextHandle ctx,
    PublicKeyHandle* pks, RotKeyHandle* shares, int n_shares,
    RotKeyHandle* out_final);
int InsertEvalSumKey(CryptoContextHandle ctx, RotKeyHandle key);

// Encrypt/Decrypt
CiphertextHandle Encrypt(CryptoContextHandle ctx, PublicKeyHandle pk,
    double* values, int n_values);
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

// Chebyshev sign approximation for argmax
CiphertextHandle EvalChebyshevSign(CryptoContextHandle ctx,
    CiphertextHandle ct, int degree);

// Polynomial evaluation: applies p(x) = sum(coeffs[i] * x^i) slot-wise.
// coeffs is in ascending order (coeffs[0] is the constant term). The
// CryptoContext must have an eval-mult key registered for any
// polynomial with degree >= 2. Returns nullptr on failure.
CiphertextHandle EvalPolynomial(CryptoContextHandle ctx,
    CiphertextHandle ct, double* coeffs, int n_coeffs);

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
    uint8_t** out_ct,
    size_t* out_ct_len,
    char* err,
    size_t err_len
);

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
