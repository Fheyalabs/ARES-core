// SPDX-License-Identifier: Apache-2.0

// OpenFHE C wrapper implementation.

#include <openfhe.h>
#include <ciphertext-ser.h>
#include <cryptocontext-ser.h>
#include <scheme/ckksrns/ckksrns-ser.h>
#include <key/key-ser.h>
#include "openfhe_wrapper.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <stdlib.h>
#include <stdexcept>
#include <string.h>
#include <string>
#include <vector>

using namespace lbcrypto;

struct ARESCryptoContext {
    CryptoContext<DCRTPoly> cc;
    uint32_t batch_size;
    std::vector<PublicKey<DCRTPoly>> public_keys;
    std::vector<PrivateKey<DCRTPoly>> secret_keys;
    EvalKey<DCRTPoly> eval_mult_base;
    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> eval_sum_base;
};

struct ARESPublicKey {
    PublicKey<DCRTPoly> pk;
};

struct ARESSecretKeyShare {
    PrivateKey<DCRTPoly> sk;
    bool lead;
};

struct ARESEvalMultKey {
    EvalKey<DCRTPoly> key;
};

struct ARESRotKey {
    std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> keys;
};

struct ARESCiphertext {
    Ciphertext<DCRTPoly> ct;
};

static ARESCryptoContext* as_ctx(CryptoContextHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE context handle");
    }
    return reinterpret_cast<ARESCryptoContext*>(handle);
}

static ARESPublicKey* as_pk(PublicKeyHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE public key handle");
    }
    return reinterpret_cast<ARESPublicKey*>(handle);
}

static ARESSecretKeyShare* as_sk(SecretKeyShareHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE secret key share handle");
    }
    return reinterpret_cast<ARESSecretKeyShare*>(handle);
}

static ARESCiphertext* as_ct(CiphertextHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE ciphertext handle");
    }
    return reinterpret_cast<ARESCiphertext*>(handle);
}

static ARESEvalMultKey* as_eval_mult(EvalMultKeyHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE eval-mult key handle");
    }
    return reinterpret_cast<ARESEvalMultKey*>(handle);
}

static ARESRotKey* as_rot(RotKeyHandle handle) {
    if (handle == nullptr) {
        throw std::runtime_error("null OpenFHE rotation/eval-sum key handle");
    }
    return reinterpret_cast<ARESRotKey*>(handle);
}

static uint32_t infer_scaling_mod_size(double scaling_factor) {
    if (!std::isfinite(scaling_factor) || scaling_factor <= 1.0) {
        return 50;
    }
    auto bits = static_cast<uint32_t>(std::round(std::log2(scaling_factor)));
    return std::min<uint32_t>(std::max<uint32_t>(bits, 30), 60);
}

static void set_error(char* err, size_t err_len, const std::string& msg) {
    if (err == nullptr || err_len == 0) {
        return;
    }
    size_t n = std::min(err_len - 1, msg.size());
    memcpy(err, msg.data(), n);
    err[n] = '\0';
}

static uint32_t next_power_of_two(uint32_t value) {
    if (value <= 1) {
        return 1;
    }
    value--;
    value |= value >> 1;
    value |= value >> 2;
    value |= value >> 4;
    value |= value >> 8;
    value |= value >> 16;
    return value + 1;
}

static double decrypt_first_slot(const CryptoContext<DCRTPoly>& cc,
    const PrivateKey<DCRTPoly>& sk,
    const Ciphertext<DCRTPoly>& ct) {
    Plaintext out;
    cc->Decrypt(sk, ct, &out);
    out->SetLength(1);
    auto values = out->GetCKKSPackedValue();
    if (values.empty()) {
        return 0.0;
    }
    return values[0].real();
}

static CryptoContext<DCRTPoly> make_ckks_context(uint32_t batch_size, uint32_t depth,
    int scaling_mod_size, int first_mod_size) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(scaling_mod_size > 0 ? scaling_mod_size : 50);
    parameters.SetFirstModSize(first_mod_size > 0 ? first_mod_size : 60);
    parameters.SetBatchSize(batch_size);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(std::max<uint32_t>(1 << 10, batch_size * 2));

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(MULTIPARTY);
    return cc;
}

static Ciphertext<DCRTPoly> encrypt_repeated_scalar(const CryptoContext<DCRTPoly>& cc,
    const PublicKey<DCRTPoly>& pk, double value, uint32_t batch_size) {
    std::vector<double> values(batch_size, value);
    auto pt = cc->MakeCKKSPackedPlaintext(values);
    return cc->Encrypt(pk, pt);
}

static Ciphertext<DCRTPoly> eval_tanh_chebyshev(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& diff, double input_scale, double gain, double bound, int degree) {
    auto scaled = diff;
    if (std::fabs(input_scale - 1.0) > 1e-12) {
        scaled = cc->EvalMult(scaled, input_scale);
    }
    auto tanh_step = [gain](double x) -> double {
        double v = gain * x;
        if (v > 20.0) {
            return 1.0;
        }
        if (v < -20.0) {
            return 0.0;
        }
        return 0.5 * (1.0 + std::tanh(v));
    };
    return cc->EvalChebyshevFunction(tanh_step, scaled, -bound, bound, static_cast<uint32_t>(degree));
}

static Ciphertext<DCRTPoly> eval_logistic_chebyshev(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& diff, double input_scale, double gain, double bound, int degree) {
    auto scaled = diff;
    if (std::fabs(input_scale - 1.0) > 1e-12) {
        scaled = cc->EvalMult(scaled, input_scale);
    }
    scaled = cc->EvalMult(scaled, gain);
    return cc->EvalLogistic(scaled, -gain * bound, gain * bound, static_cast<uint32_t>(degree));
}

static Ciphertext<DCRTPoly> smoothstep5(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& x) {
    auto x2 = cc->EvalMult(x, x);
    auto x3 = cc->EvalMult(x2, x);
    auto six_x = cc->EvalMult(x, 6.0);
    auto inner = cc->EvalAdd(cc->EvalMult(x, cc->EvalAdd(six_x, -15.0)), 10.0);
    return cc->EvalMult(x3, inner);
}

static Ciphertext<DCRTPoly> smoothstep7(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& x) {
    auto x2 = cc->EvalMult(x, x);
    auto x4 = cc->EvalMult(x2, x2);
    auto inner = cc->EvalAdd(
        cc->EvalMult(
            x,
            cc->EvalAdd(
                cc->EvalMult(
                    x,
                    cc->EvalAdd(cc->EvalMult(x, -20.0), 70.0)
                ),
                -84.0
            )
        ),
        35.0
    );
    return cc->EvalMult(x4, inner);
}

static std::vector<std::string> split_schedule(const char* raw_schedule) {
    std::vector<std::string> out;
    std::string s = raw_schedule == nullptr ? "" : std::string(raw_schedule);
    std::string lowered = s;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    lowered.erase(lowered.begin(), std::find_if(lowered.begin(), lowered.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    lowered.erase(std::find_if(lowered.rbegin(), lowered.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), lowered.end());
    if (lowered == "none" || lowered == "identity") {
        return out;
    }
    size_t start = 0;
    while (start <= s.size()) {
        size_t end = s.find(',', start);
        std::string part = s.substr(start, end == std::string::npos ? std::string::npos : end - start);
        part.erase(part.begin(), std::find_if(part.begin(), part.end(), [](unsigned char ch) { return !std::isspace(ch); }));
        part.erase(std::find_if(part.rbegin(), part.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), part.end());
        if (!part.empty()) {
            out.push_back(part);
        }
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    if (out.empty()) {
        out = {"smoothstep5", "smoothstep5", "smoothstep5", "smoothstep7"};
    }
    return out;
}

static Ciphertext<DCRTPoly> apply_selector_schedule(const CryptoContext<DCRTPoly>& cc,
    Ciphertext<DCRTPoly> selector, const std::vector<std::string>& schedule) {
    for (const auto& mode : schedule) {
        if (mode == "smoothstep5") {
            selector = smoothstep5(cc, selector);
        } else if (mode == "smoothstep7") {
            selector = smoothstep7(cc, selector);
        } else {
            throw std::runtime_error("unsupported selector schedule stage: " + mode);
        }
    }
    return selector;
}

static Ciphertext<DCRTPoly> product_tree(const CryptoContext<DCRTPoly>& cc,
    std::vector<Ciphertext<DCRTPoly>> factors) {
    if (factors.empty()) {
        throw std::runtime_error("product tree requires at least one factor");
    }
    while (factors.size() > 1) {
        std::vector<Ciphertext<DCRTPoly>> next;
        next.reserve((factors.size() + 1) / 2);
        for (size_t i = 0; i + 1 < factors.size(); i += 2) {
            next.push_back(cc->EvalMult(factors[i], factors[i + 1]));
        }
        if (factors.size() % 2 == 1) {
            next.push_back(factors.back());
        }
        factors = std::move(next);
    }
    return factors[0];
}

static Ciphertext<DCRTPoly> broadcast_first_slot(const CryptoContext<DCRTPoly>& cc,
    const Ciphertext<DCRTPoly>& ct, int slot_count, uint32_t batch_size) {
    std::vector<double> first_only(batch_size, 0.0);
    first_only[0] = 1.0;
    auto first_pt = cc->MakeCKKSPackedPlaintext(first_only);
    auto out = cc->EvalMult(ct, first_pt);
    for (int shift = 1; shift < slot_count; shift *= 2) {
        auto rotated = cc->EvalRotate(out, -shift);
        out = cc->EvalAdd(out, rotated);
    }
    return out;
}

static std::vector<int32_t> broadcast_rotation_indices(uint32_t batch_size) {
    std::vector<int32_t> indices;
    for (uint32_t shift = 1; shift < batch_size; shift *= 2) {
        indices.push_back(static_cast<int32_t>(shift));
        indices.push_back(-static_cast<int32_t>(shift));
    }
    return indices;
}

static std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> clone_key_map(
    const std::map<usint, EvalKey<DCRTPoly>>& keys
) {
    return std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(keys);
}

static void merge_key_maps(
    const std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>>& into,
    const std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>>& from
) {
    for (const auto& item : *from) {
        (*into)[item.first] = item.second;
    }
}

static std::vector<double> package_bits_for_candidate(const int* candidate_packages,
    int candidate_index, int package_bytes, int payload_slot_count, uint32_t batch_size) {
    std::vector<double> bits(batch_size, 0.0);
    int available_bits = package_bytes * 8;
    int n_bits = std::min(payload_slot_count, available_bits);
    const int* pkg = candidate_packages + (static_cast<size_t>(candidate_index) * package_bytes);
    for (int bit_idx = 0; bit_idx < n_bits; bit_idx++) {
        int value = pkg[bit_idx / 8];
        int shift = 7 - (bit_idx % 8);
        bits[bit_idx] = ((value >> shift) & 1) ? 1.0 : 0.0;
    }
    return bits;
}

static ARESCryptoContext make_threshold_context(uint32_t batch_size, uint32_t depth,
    int scaling_mod_size, int first_mod_size, int parties) {
    if (parties < 2) {
        throw std::runtime_error("threshold context requires at least two parties");
    }
    ARESCryptoContext ctx{
        make_ckks_context(batch_size, depth, scaling_mod_size, first_mod_size),
        batch_size,
        {},
        {},
        nullptr,
        nullptr,
    };
    auto kp = ctx.cc->KeyGen();
    if (!kp.good()) {
        throw std::runtime_error("threshold key generation failed for lead party");
    }
    ctx.public_keys.push_back(kp.publicKey);
    ctx.secret_keys.push_back(kp.secretKey);
    for (int i = 1; i < parties; i++) {
        kp = ctx.cc->MultipartyKeyGen(ctx.public_keys.back());
        if (!kp.good()) {
            throw std::runtime_error("threshold key generation failed for participant");
        }
        ctx.public_keys.push_back(kp.publicKey);
        ctx.secret_keys.push_back(kp.secretKey);
    }
    return ctx;
}

static std::vector<double> threshold_decrypt_slots(ARESCryptoContext* ctx,
    const Ciphertext<DCRTPoly>& ct, int n_values) {
    if (ctx == nullptr || ctx->secret_keys.empty()) {
        throw std::runtime_error("threshold decrypt requires key shares");
    }
    std::vector<Ciphertext<DCRTPoly>> partials;
    partials.reserve(ctx->secret_keys.size());
    auto lead = ctx->cc->MultipartyDecryptLead({ct}, ctx->secret_keys[0]);
    if (lead.empty()) {
        throw std::runtime_error("threshold lead decrypt returned no partial");
    }
    partials.push_back(lead[0]);
    for (size_t i = 1; i < ctx->secret_keys.size(); i++) {
        auto main = ctx->cc->MultipartyDecryptMain({ct}, ctx->secret_keys[i]);
        if (main.empty()) {
            throw std::runtime_error("threshold participant decrypt returned no partial");
        }
        partials.push_back(main[0]);
    }
    Plaintext out;
    ctx->cc->MultipartyDecryptFusion(partials, &out);
    out->SetLength(static_cast<size_t>(n_values));
    auto slots = out->GetCKKSPackedValue();
    std::vector<double> values(static_cast<size_t>(n_values), 0.0);
    for (int i = 0; i < n_values && i < static_cast<int>(slots.size()); i++) {
        values[i] = slots[i].real();
    }
    return values;
}

static void rebuild_eval_mult_keys(ARESCryptoContext* ctx) {
    if (ctx->secret_keys.empty()) {
        throw std::runtime_error("cannot build eval-mult keys before threshold keygen");
    }
    if (ctx->secret_keys.size() == 1) {
        ctx->cc->EvalMultKeyGen(ctx->secret_keys[0]);
        return;
    }

    auto base = ctx->cc->KeySwitchGen(ctx->secret_keys[0], ctx->secret_keys[0]);
    auto joined = base;
    for (size_t i = 1; i < ctx->secret_keys.size(); i++) {
        auto share = ctx->cc->MultiKeySwitchGen(ctx->secret_keys[i], ctx->secret_keys[i], base);
        joined = ctx->cc->MultiAddEvalKeys(joined, share, ctx->public_keys[i]->GetKeyTag());
    }

    std::vector<EvalKey<DCRTPoly>> transformed;
    transformed.reserve(ctx->secret_keys.size());
    const std::string final_tag = ctx->public_keys.back()->GetKeyTag();
    for (const auto& sk : ctx->secret_keys) {
        transformed.push_back(ctx->cc->MultiMultEvalKey(sk, joined, final_tag));
    }

    auto combined = transformed[0];
    for (size_t i = 1; i < transformed.size(); i++) {
        combined = ctx->cc->MultiAddEvalMultKeys(combined, transformed[i], final_tag);
    }
    ctx->cc->InsertEvalMultKey({combined});
    ctx->eval_mult_base = joined;
}

static std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> rebuild_eval_sum_keys(ARESCryptoContext* ctx) {
    if (ctx->secret_keys.empty()) {
        throw std::runtime_error("cannot build eval-sum keys before threshold keygen");
    }
    ctx->cc->EvalSumKeyGen(ctx->secret_keys[0]);
    auto base = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(
        ctx->cc->GetEvalSumKeyMap(ctx->secret_keys[0]->GetKeyTag()));
    auto joined = base;
    for (size_t i = 1; i < ctx->secret_keys.size(); i++) {
        auto share = ctx->cc->MultiEvalSumKeyGen(ctx->secret_keys[i], base, ctx->public_keys[i]->GetKeyTag());
        joined = ctx->cc->MultiAddEvalSumKeys(joined, share, ctx->public_keys[i]->GetKeyTag());
    }
    ctx->cc->InsertEvalSumKey(joined);
    ctx->eval_sum_base = base;
    return joined;
}

template <typename T>
static int serialize_object(const T& obj, uint8_t** out_data, size_t* out_len) {
    if (out_data == nullptr || out_len == nullptr) {
        return 1;
    }
    std::stringstream os;
    Serial::Serialize(obj, os, SerType::BINARY);
    auto raw = os.str();
    auto* buf = reinterpret_cast<uint8_t*>(malloc(raw.size()));
    if (buf == nullptr && !raw.empty()) {
        return 1;
    }
    if (!raw.empty()) {
        memcpy(buf, raw.data(), raw.size());
    }
    *out_data = buf;
    *out_len = raw.size();
    return 0;
}

extern "C" {

CryptoContextHandle CreateCKKSContext(uint32_t ring_dim, double scaling_factor, uint32_t depth) {
    try {
        uint32_t batch_size = ring_dim >= 16 ? ring_dim / 2 : 8;
        int scaling_mod_size = static_cast<int>(infer_scaling_mod_size(scaling_factor));
        auto* ctx = new ARESCryptoContext{
            make_ckks_context(batch_size, depth == 0 ? 2 : depth, scaling_mod_size, 60),
            batch_size,
            {},
            {},
            nullptr,
            nullptr,
        };
        return reinterpret_cast<CryptoContextHandle>(ctx);
    } catch (...) {
        return nullptr;
    }
}

void FreeCryptoContext(CryptoContextHandle ctx) {
    delete reinterpret_cast<ARESCryptoContext*>(ctx);
}

int KeyGenFirst(CryptoContextHandle ctx, PublicKeyHandle* out_pk, SecretKeyShareHandle* out_sk) {
    try {
        if (out_pk == nullptr || out_sk == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto kp = c->cc->KeyGen();
        if (!kp.good()) {
            return 1;
        }
        c->public_keys.clear();
        c->secret_keys.clear();
        c->public_keys.push_back(kp.publicKey);
        c->secret_keys.push_back(kp.secretKey);
        *out_pk = reinterpret_cast<PublicKeyHandle>(new ARESPublicKey{kp.publicKey});
        *out_sk = reinterpret_cast<SecretKeyShareHandle>(new ARESSecretKeyShare{kp.secretKey, true});
        return 0;
    } catch (...) {
        return 1;
    }
}

int KeyGenNext(CryptoContextHandle ctx, PublicKeyHandle prev_pk,
    PublicKeyHandle* out_pk, SecretKeyShareHandle* out_sk) {
    try {
        if (out_pk == nullptr || out_sk == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* prev = as_pk(prev_pk);
        auto kp = c->cc->MultipartyKeyGen(prev->pk);
        if (!kp.good()) {
            return 1;
        }
        c->public_keys.push_back(kp.publicKey);
        c->secret_keys.push_back(kp.secretKey);
        *out_pk = reinterpret_cast<PublicKeyHandle>(new ARESPublicKey{kp.publicKey});
        *out_sk = reinterpret_cast<SecretKeyShareHandle>(new ARESSecretKeyShare{kp.secretKey, false});
        return 0;
    } catch (...) {
        return 1;
    }
}

int MultiAddPublicKeys(CryptoContextHandle ctx, PublicKeyHandle* pks, int n_keys, PublicKeyHandle* out_joint) {
    try {
        if (pks == nullptr || out_joint == nullptr || n_keys <= 0) {
            return 1;
        }
        (void)as_ctx(ctx);
        // KeyGenNext already returns the cumulative OpenFHE joint key, so the
        // final chained public key is the production encryption key.
        *out_joint = reinterpret_cast<PublicKeyHandle>(new ARESPublicKey{as_pk(pks[n_keys - 1])->pk});
        return 0;
    } catch (...) {
        return 1;
    }
}

int GenEvalMultKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk, EvalMultKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        if (c->secret_keys.empty()) {
            c->secret_keys.push_back(s->sk);
        }
        if (c->eval_mult_base == nullptr) {
            rebuild_eval_mult_keys(c);
        }
        auto share = c->cc->KeySwitchGen(s->sk, s->sk);
        *out_share = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{share});
        return 0;
    } catch (...) {
        return 1;
    }
}
int GenRotKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk, RotKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        (void)as_sk(sk);
        auto* c = as_ctx(ctx);
        auto keys = c->eval_sum_base == nullptr ? rebuild_eval_sum_keys(c) : c->eval_sum_base;
        *out_share = reinterpret_cast<RotKeyHandle>(new ARESRotKey{keys});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalMultKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk, EvalMultKeyHandle* out_base) {
    try {
        if (out_base == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        auto base = c->cc->KeySwitchGen(s->sk, s->sk);
        *out_base = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{base});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalMultKeySwitchShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle base, EvalMultKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        auto share = c->cc->MultiKeySwitchGen(s->sk, s->sk, as_eval_mult(base)->key);
        *out_share = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{share});
        return 0;
    } catch (...) {
        return 1;
    }
}

int CombineEvalMultSwitchShares(CryptoContextHandle ctx,
    PublicKeyHandle* pks, EvalMultKeyHandle* shares, int n_shares,
    EvalMultKeyHandle* out_joined) {
    try {
        if (pks == nullptr || shares == nullptr || out_joined == nullptr || n_shares <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto joined = as_eval_mult(shares[0])->key;
        for (int i = 1; i < n_shares; i++) {
            joined = c->cc->MultiAddEvalKeys(joined, as_eval_mult(shares[i])->key, as_pk(pks[i])->pk->GetKeyTag());
        }
        *out_joined = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{joined});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalMultKeyFinalShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    EvalMultKeyHandle joined, PublicKeyHandle final_pk,
    EvalMultKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        const std::string final_tag = as_pk(final_pk)->pk->GetKeyTag();
        auto transformed = c->cc->MultiMultEvalKey(s->sk, as_eval_mult(joined)->key, final_tag);
        *out_share = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{transformed});
        return 0;
    } catch (...) {
        return 1;
    }
}

int CombineEvalMultFinalShares(CryptoContextHandle ctx, PublicKeyHandle final_pk,
    EvalMultKeyHandle* shares, int n_shares,
    EvalMultKeyHandle* out_final) {
    try {
        if (shares == nullptr || out_final == nullptr || n_shares <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        const std::string final_tag = as_pk(final_pk)->pk->GetKeyTag();
        auto combined = as_eval_mult(shares[0])->key;
        for (int i = 1; i < n_shares; i++) {
            combined = c->cc->MultiAddEvalMultKeys(combined, as_eval_mult(shares[i])->key, final_tag);
        }
        *out_final = reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{combined});
        return 0;
    } catch (...) {
        return 1;
    }
}

int InsertEvalMultKey(CryptoContextHandle ctx, EvalMultKeyHandle key) {
    try {
        auto* c = as_ctx(ctx);
        c->cc->InsertEvalMultKey({as_eval_mult(key)->key});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalSumKeyGenLead(CryptoContextHandle ctx, SecretKeyShareHandle sk, RotKeyHandle* out_base) {
    try {
        if (out_base == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        c->cc->EvalSumKeyGen(s->sk);
        c->cc->EvalAtIndexKeyGen(s->sk, broadcast_rotation_indices(c->batch_size));
        auto keys = clone_key_map(c->cc->GetEvalAutomorphismKeyMap(s->sk->GetKeyTag()));
        *out_base = reinterpret_cast<RotKeyHandle>(new ARESRotKey{keys});
        return 0;
    } catch (...) {
        return 1;
    }
}

int EvalSumKeyShare(CryptoContextHandle ctx, SecretKeyShareHandle sk,
    RotKeyHandle base, PublicKeyHandle own_pk,
    RotKeyHandle* out_share) {
    try {
        if (out_share == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* s = as_sk(sk);
        const std::string key_tag = as_pk(own_pk)->pk->GetKeyTag();
        auto share = c->cc->MultiEvalSumKeyGen(s->sk, as_rot(base)->keys, key_tag);
        auto rotate_share = c->cc->MultiEvalAtIndexKeyGen(
            s->sk,
            as_rot(base)->keys,
            broadcast_rotation_indices(c->batch_size),
            key_tag
        );
        merge_key_maps(share, rotate_share);
        *out_share = reinterpret_cast<RotKeyHandle>(new ARESRotKey{share});
        return 0;
    } catch (...) {
        return 1;
    }
}

int CombineEvalSumKeys(CryptoContextHandle ctx,
    PublicKeyHandle* pks, RotKeyHandle* shares, int n_shares,
    RotKeyHandle* out_final) {
    try {
        if (pks == nullptr || shares == nullptr || out_final == nullptr || n_shares <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto joined = as_rot(shares[0])->keys;
        for (int i = 1; i < n_shares; i++) {
            joined = c->cc->MultiAddEvalAutomorphismKeys(joined, as_rot(shares[i])->keys, as_pk(pks[i])->pk->GetKeyTag());
        }
        *out_final = reinterpret_cast<RotKeyHandle>(new ARESRotKey{joined});
        return 0;
    } catch (...) {
        return 1;
    }
}

int InsertEvalSumKey(CryptoContextHandle ctx, RotKeyHandle key) {
    try {
        auto* c = as_ctx(ctx);
        c->cc->InsertEvalSumKey(as_rot(key)->keys);
        return 0;
    } catch (...) {
        return 1;
    }
}

CiphertextHandle Encrypt(CryptoContextHandle ctx, PublicKeyHandle pk, double* values, int n_values) {
    try {
        if (values == nullptr || n_values <= 0) {
            return nullptr;
        }
        auto* c = as_ctx(ctx);
        auto* p = as_pk(pk);
        std::vector<double> packed(c->batch_size, 0.0);
        for (int i = 0; i < n_values && i < static_cast<int>(packed.size()); i++) {
            packed[i] = values[i];
        }
        auto pt = c->cc->MakeCKKSPackedPlaintext(packed);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->Encrypt(p->pk, pt)});
    } catch (...) {
        return nullptr;
    }
}

int MultiDecMain(CryptoContextHandle ctx, CiphertextHandle ct, SecretKeyShareHandle sk, CiphertextHandle* out_partial) {
    try {
        if (out_partial == nullptr) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        auto* cipher = as_ct(ct);
        auto* share = as_sk(sk);
        std::vector<Ciphertext<DCRTPoly>> partials = share->lead
            ? c->cc->MultipartyDecryptLead({cipher->ct}, share->sk)
            : c->cc->MultipartyDecryptMain({cipher->ct}, share->sk);
        if (partials.empty()) {
            return 1;
        }
        *out_partial = reinterpret_cast<CiphertextHandle>(new ARESCiphertext{partials[0]});
        return 0;
    } catch (...) {
        return 1;
    }
}

int MultiDecFusion(CryptoContextHandle ctx, CiphertextHandle* partials, int n_partials, double* out_values, int* out_n_values) {
    try {
        if (partials == nullptr || out_values == nullptr || out_n_values == nullptr || n_partials <= 0) {
            return 1;
        }
        auto* c = as_ctx(ctx);
        std::vector<Ciphertext<DCRTPoly>> partial_vec;
        partial_vec.reserve(static_cast<size_t>(n_partials));
        for (int i = 0; i < n_partials; i++) {
            partial_vec.push_back(as_ct(partials[i])->ct);
        }
        Plaintext out;
        c->cc->MultipartyDecryptFusion(partial_vec, &out);
        int capacity = *out_n_values > 0 ? *out_n_values : static_cast<int>(c->batch_size);
        out->SetLength(static_cast<size_t>(capacity));
        auto slots = out->GetCKKSPackedValue();
        int count = std::min(capacity, static_cast<int>(slots.size()));
        for (int i = 0; i < count; i++) {
            out_values[i] = slots[i].real();
        }
        *out_n_values = count;
        return 0;
    } catch (...) {
        return 1;
    }
}

CiphertextHandle EvalAdd(CryptoContextHandle ctx, CiphertextHandle a, CiphertextHandle b) {
    try {
        auto* c = as_ctx(ctx);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalAdd(as_ct(a)->ct, as_ct(b)->ct)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalMult(CryptoContextHandle ctx, CiphertextHandle a, CiphertextHandle b) {
    try {
        auto* c = as_ctx(ctx);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalMult(as_ct(a)->ct, as_ct(b)->ct)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalSum(CryptoContextHandle ctx, CiphertextHandle ct, int batch_size) {
    try {
        auto* c = as_ctx(ctx);
        int n = batch_size > 0 ? batch_size : static_cast<int>(c->batch_size);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalSum(as_ct(ct)->ct, n)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalMultConst(CryptoContextHandle ctx, CiphertextHandle ct, double scalar) {
    try {
        auto* c = as_ctx(ctx);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalMult(as_ct(ct)->ct, scalar)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalSub(CryptoContextHandle ctx, CiphertextHandle a, CiphertextHandle b) {
    try {
        auto* c = as_ctx(ctx);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{c->cc->EvalSub(as_ct(a)->ct, as_ct(b)->ct)});
    } catch (...) {
        return nullptr;
    }
}
CiphertextHandle EvalChebyshevSign(CryptoContextHandle ctx, CiphertextHandle ct, int degree) {
    try {
        auto* c = as_ctx(ctx);
        auto sign = [](double x) -> double {
            return x >= 0.0 ? 1.0 : 0.0;
        };
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{
            c->cc->EvalChebyshevFunction(sign, as_ct(ct)->ct, -1.0, 1.0, static_cast<uint32_t>(std::max(3, degree)))
        });
    } catch (...) {
        return nullptr;
    }
}

CiphertextHandle EvalPolynomial(CryptoContextHandle ctx, CiphertextHandle ct, double* coeffs, int n_coeffs) {
    try {
        if (n_coeffs <= 0 || coeffs == nullptr) {
            return nullptr;
        }
        auto* c = as_ctx(ctx);
        std::vector<double> coefficients(coeffs, coeffs + n_coeffs);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{
            c->cc->EvalPoly(as_ct(ct)->ct, coefficients)
        });
    } catch (const std::exception& e) {
        std::cerr << "[openfhe] EvalPolynomial failed: " << e.what() << std::endl;
        return nullptr;
    } catch (...) {
        return nullptr;
    }
}

int EvalArgmax(CryptoContextHandle ctx,
               const CiphertextHandle* cts, int n_cts,
               const double* sharp_coeffs, int n_sharp_coeffs,
               CiphertextHandle* out_masks) {
    try {
        if (n_cts < 2 || cts == nullptr) return -1;
        if (n_sharp_coeffs < 2 || sharp_coeffs == nullptr) return -2;
        if (out_masks == nullptr) return -3;
        auto* c = as_ctx(ctx);
        std::vector<double> coeffs(sharp_coeffs, sharp_coeffs + n_sharp_coeffs);

        // Precompute sharp(cts[i] - cts[j]) once per ordered pair.
        // For i != j: pair[i][j] = p(cts[i] - cts[j]) ≈ 1 if cts[i] > cts[j], ≈ 0 otherwise.
        // mask[i] = ∏_{j != i} pair[i][j].
        std::vector<std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>> pair(
            n_cts, std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>(n_cts));
        for (int i = 0; i < n_cts; ++i) {
            for (int j = 0; j < n_cts; ++j) {
                if (i == j) continue;
                auto diff = c->cc->EvalSub(as_ct(cts[i])->ct, as_ct(cts[j])->ct);
                pair[i][j] = c->cc->EvalPoly(diff, coeffs);
            }
        }

        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> masks(n_cts);
        for (int i = 0; i < n_cts; ++i) {
            lbcrypto::Ciphertext<lbcrypto::DCRTPoly> acc;
            bool first = true;
            for (int j = 0; j < n_cts; ++j) {
                if (i == j) continue;
                if (first) {
                    acc = pair[i][j];
                    first = false;
                } else {
                    acc = c->cc->EvalMult(acc, pair[i][j]);
                }
            }
            masks[i] = acc;
        }

        for (int i = 0; i < n_cts; ++i) {
            out_masks[i] = reinterpret_cast<CiphertextHandle>(new ARESCiphertext{masks[i]});
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[openfhe] EvalArgmax failed: " << e.what() << std::endl;
        return -100;
    } catch (...) {
        return -101;
    }
}

int SerializeCiphertext(CiphertextHandle ct, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(as_ct(ct)->ct, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
CiphertextHandle DeserializeCiphertext(CryptoContextHandle ctx, uint8_t* data, size_t len) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        Ciphertext<DCRTPoly> ct;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(ct, is, SerType::BINARY);
        return reinterpret_cast<CiphertextHandle>(new ARESCiphertext{ct});
    } catch (...) {
        return nullptr;
    }
}
int SerializePublicKey(PublicKeyHandle pk, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(as_pk(pk)->pk, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
PublicKeyHandle DeserializePublicKey(CryptoContextHandle ctx, uint8_t* data, size_t len) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        PublicKey<DCRTPoly> pk;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(pk, is, SerType::BINARY);
        return reinterpret_cast<PublicKeyHandle>(new ARESPublicKey{pk});
    } catch (...) {
        return nullptr;
    }
}
int SerializeSecretKeyShare(SecretKeyShareHandle sk, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(as_sk(sk)->sk, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
SecretKeyShareHandle DeserializeSecretKeyShare(CryptoContextHandle ctx, uint8_t* data, size_t len, int lead) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        PrivateKey<DCRTPoly> sk;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(sk, is, SerType::BINARY);
        return reinterpret_cast<SecretKeyShareHandle>(new ARESSecretKeyShare{sk, lead != 0});
    } catch (...) {
        return nullptr;
    }
}
int SerializeEvalMultKey(EvalMultKeyHandle key, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(as_eval_mult(key)->key, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
EvalMultKeyHandle DeserializeEvalMultKey(CryptoContextHandle ctx, uint8_t* data, size_t len) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        EvalKey<DCRTPoly> key;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(key, is, SerType::BINARY);
        return reinterpret_cast<EvalMultKeyHandle>(new ARESEvalMultKey{key});
    } catch (...) {
        return nullptr;
    }
}
int SerializeRotKey(RotKeyHandle key, uint8_t** out_data, size_t* out_len) {
    try {
        return serialize_object(*as_rot(key)->keys, out_data, out_len);
    } catch (...) {
        return 1;
    }
}
RotKeyHandle DeserializeRotKey(CryptoContextHandle ctx, uint8_t* data, size_t len) {
    try {
        (void)as_ctx(ctx);
        if (data == nullptr || len == 0) {
            return nullptr;
        }
        std::map<usint, EvalKey<DCRTPoly>> keys;
        std::string raw(reinterpret_cast<const char*>(data), len);
        std::stringstream is(raw);
        Serial::Deserialize(keys, is, SerType::BINARY);
        auto ptr = std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(keys);
        return reinterpret_cast<RotKeyHandle>(new ARESRotKey{ptr});
    } catch (...) {
        return nullptr;
    }
}

void FreePublicKey(PublicKeyHandle pk) { delete reinterpret_cast<ARESPublicKey*>(pk); }
void FreeSecretKeyShare(SecretKeyShareHandle sk) { delete reinterpret_cast<ARESSecretKeyShare*>(sk); }
void FreeCiphertext(CiphertextHandle ct) { delete reinterpret_cast<ARESCiphertext*>(ct); }
void FreeEvalMultKey(EvalMultKeyHandle key) { delete reinterpret_cast<ARESEvalMultKey*>(key); }
void FreeRotKey(RotKeyHandle key) { delete reinterpret_cast<ARESRotKey*>(key); }

int ARESOpenFHESmoke(char* err, size_t err_len) {
    try {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(2);
        parameters.SetScalingModSize(50);
        parameters.SetFirstModSize(60);
        parameters.SetBatchSize(8);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 8);

        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);

        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        std::vector<double> values = {1.0, 2.0, 3.0, 4.0};
        auto pt = cc->MakeCKKSPackedPlaintext(values);
        auto ct = cc->Encrypt(keys.publicKey, pt);
        auto sq = cc->EvalMult(ct, ct);
        Plaintext out;
        cc->Decrypt(keys.secretKey, sq, &out);
        out->SetLength(values.size());
        auto slots = out->GetCKKSPackedValue();
        double got = 0.0;
        for (size_t i = 0; i < values.size() && i < slots.size(); i++) {
            got += slots[i].real();
        }
        if (std::fabs(got - 30.0) > 0.01) {
            set_error(err, err_len, "OpenFHE smoke dot product mismatch");
            return 1;
        }
        return 0;
    } catch (const std::exception& ex) {
        set_error(err, err_len, ex.what());
        return 1;
    } catch (...) {
        set_error(err, err_len, "unknown OpenFHE smoke failure");
        return 1;
    }
}

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
) {
    try {
        if (initiator_profile == nullptr || candidate_profiles == nullptr || candidate_packages == nullptr ||
            out_scores == nullptr || out_mask_values == nullptr || out_payload_values == nullptr ||
            out_winner_index == nullptr || out_winner_score == nullptr) {
            set_error(err, err_len, "null pointer passed to ARESScoreCandidatesCKKS");
            return 1;
        }
        if (profile_dim <= 0 || n_candidates <= 0) {
            set_error(err, err_len, "invalid profile_dim or n_candidates");
            return 1;
        }
        if (package_bytes <= 0 || payload_slot_count < package_bytes * 8) {
            set_error(err, err_len, "invalid package_bytes or payload_slot_count");
            return 1;
        }
        std::string mask_mode_value = mask_mode == nullptr ? "multiplicative" : std::string(mask_mode);
        if (mask_mode_value != "multiplicative") {
            set_error(err, err_len, "native OpenFHE scorer currently supports only multiplicative masks");
            return 1;
        }
        std::string comparator_value = comparator == nullptr ? "tanh_chebyshev" : std::string(comparator);
        if (comparator_value.empty()) {
            comparator_value = "tanh_chebyshev";
        }
        if (comparator_value != "tanh_chebyshev" && comparator_value != "logistic") {
            set_error(err, err_len, "native OpenFHE scorer supports tanh_chebyshev or logistic comparators");
            return 1;
        }
        if (comparator_degree <= 0) {
            comparator_degree = 27;
        }
        if (comparator_gain == 0.0) {
            comparator_gain = 100.0;
        }
        if (comparator_input_scale == 0.0) {
            comparator_input_scale = 0.5;
        }
        if (comparator_bound == 0.0) {
            comparator_bound = 0.5;
        }

        uint32_t batch_size = next_power_of_two(static_cast<uint32_t>(std::max(profile_dim, 32)));
        auto cc = make_ckks_context(batch_size, 3, scaling_mod_size, first_mod_size);

        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        std::vector<double> init_vec(batch_size, 0.0);
        for (int i = 0; i < profile_dim; i++) {
            init_vec[i] = initiator_profile[i];
        }
        auto init_pt = cc->MakeCKKSPackedPlaintext(init_vec);
        auto init_ct = cc->Encrypt(keys.publicKey, init_pt);

        bool sqrt_distance = distance_function != nullptr &&
            std::string(distance_function) == "polynomial_sqrt_approximation";
        int winner = -1;
        double winner_score = -std::numeric_limits<double>::infinity();

        for (int cand = 0; cand < n_candidates; cand++) {
            std::vector<double> cand_vec(batch_size, 0.0);
            const double* profile = candidate_profiles + (static_cast<size_t>(cand) * profile_dim);
            for (int j = 0; j < profile_dim; j++) {
                cand_vec[j] = profile[j];
            }
            auto cand_pt = cc->MakeCKKSPackedPlaintext(cand_vec);
            auto cand_ct = cc->Encrypt(keys.publicKey, cand_pt);
            auto prod_ct = cc->EvalMult(init_ct, cand_ct);
            Plaintext prod_pt;
            cc->Decrypt(keys.secretKey, prod_ct, &prod_pt);
            prod_pt->SetLength(profile_dim);
            auto prod_slots = prod_pt->GetCKKSPackedValue();
            double sim = 0.0;
            for (int j = 0; j < profile_dim && j < static_cast<int>(prod_slots.size()); j++) {
                sim += prod_slots[j].real();
            }

            double dlat = static_cast<double>(initiator_lat_q - candidate_lat_q[cand]);
            double dlon = static_cast<double>(initiator_lon_q - candidate_lon_q[cand]);
            double dist = dlat * dlat + dlon * dlon;
            if (sqrt_distance) {
                double x = dist;
                dist = 0.5 + x * (0.015 + x * (-1.2e-6 + x * 5.5e-11));
            }

            double score = -alpha * dist + (beta / 2.0) * sim + (beta / 2.0) +
                gamma * static_cast<double>(candidate_brownies[cand]);
            out_scores[cand] = score;
            if (winner < 0 || score > winner_score) {
                winner = cand;
                winner_score = score;
            }
        }

        uint32_t selector_batch = 8;
        uint32_t selector_depth = 30;
        auto selector_cc = make_ckks_context(selector_batch, selector_depth, scaling_mod_size, first_mod_size);
        auto selector_keys = selector_cc->KeyGen();
        selector_cc->EvalMultKeyGen(selector_keys.secretKey);

        std::vector<Ciphertext<DCRTPoly>> ct_scores;
        ct_scores.reserve(n_candidates);
        for (int i = 0; i < n_candidates; i++) {
            ct_scores.push_back(encrypt_repeated_scalar(selector_cc, selector_keys.publicKey, out_scores[i], selector_batch));
        }

        auto schedule = split_schedule(selector_schedule);
        std::vector<std::vector<Ciphertext<DCRTPoly>>> selectors(
            static_cast<size_t>(n_candidates),
            std::vector<Ciphertext<DCRTPoly>>(static_cast<size_t>(n_candidates))
        );
        for (int i = 0; i < n_candidates; i++) {
            selectors[i][i] = encrypt_repeated_scalar(selector_cc, selector_keys.publicKey, 1.0, selector_batch);
        }
        for (int i = 0; i < n_candidates; i++) {
            for (int j = i + 1; j < n_candidates; j++) {
                auto diff = selector_cc->EvalSub(ct_scores[i], ct_scores[j]);
                Ciphertext<DCRTPoly> sel_ij;
                if (comparator_value == "logistic") {
                    sel_ij = eval_logistic_chebyshev(
                        selector_cc,
                        diff,
                        comparator_input_scale,
                        comparator_gain,
                        comparator_bound,
                        comparator_degree
                    );
                } else {
                    sel_ij = eval_tanh_chebyshev(
                        selector_cc,
                        diff,
                        comparator_input_scale,
                        comparator_gain,
                        comparator_bound,
                        comparator_degree
                    );
                }
                sel_ij = apply_selector_schedule(selector_cc, sel_ij, schedule);
                auto one = encrypt_repeated_scalar(selector_cc, selector_keys.publicKey, 1.0, selector_batch);
                selectors[i][j] = sel_ij;
                selectors[j][i] = selector_cc->EvalSub(one, sel_ij);
            }
        }

        std::vector<double> mask_values(static_cast<size_t>(n_candidates), 0.0);
        for (int i = 0; i < n_candidates; i++) {
            std::vector<Ciphertext<DCRTPoly>> factors;
            factors.reserve(static_cast<size_t>(std::max(0, n_candidates - 1)));
            for (int j = 0; j < n_candidates; j++) {
                if (i == j) {
                    continue;
                }
                factors.push_back(selectors[i][j]);
            }
            auto mask_ct = product_tree(selector_cc, factors);
            mask_values[i] = decrypt_first_slot(selector_cc, selector_keys.secretKey, mask_ct);
            out_mask_values[i] = mask_values[i];
        }

        uint32_t payload_batch = next_power_of_two(static_cast<uint32_t>(std::max(payload_slot_count, 32)));
        auto payload_ctx = make_threshold_context(
            payload_batch,
            3,
            scaling_mod_size,
            first_mod_size,
            std::max(2, n_candidates + 1)
        );
        rebuild_eval_mult_keys(&payload_ctx);

        Ciphertext<DCRTPoly> fused_payload;
        bool have_payload = false;
        for (int i = 0; i < n_candidates; i++) {
            auto mask_ct = encrypt_repeated_scalar(payload_ctx.cc, payload_ctx.public_keys.back(), mask_values[i], payload_batch);
            auto bits = package_bits_for_candidate(candidate_packages, i, package_bytes, payload_slot_count, payload_batch);
            auto bits_pt = payload_ctx.cc->MakeCKKSPackedPlaintext(bits);
            auto bits_ct = payload_ctx.cc->Encrypt(payload_ctx.public_keys.back(), bits_pt);
            auto weighted = payload_ctx.cc->EvalMult(mask_ct, bits_ct);
            fused_payload = have_payload ? payload_ctx.cc->EvalAdd(fused_payload, weighted) : weighted;
            have_payload = true;
        }
        if (!have_payload) {
            set_error(err, err_len, "payload fusion produced no ciphertext");
            return 1;
        }

        auto payload_slots = threshold_decrypt_slots(&payload_ctx, fused_payload, payload_slot_count);
        for (int i = 0; i < payload_slot_count; i++) {
            out_payload_values[i] = i < static_cast<int>(payload_slots.size()) ? payload_slots[i] : 0.0;
        }

        *out_winner_index = winner;
        *out_winner_score = winner_score;
        return 0;
    } catch (const std::exception& ex) {
        set_error(err, err_len, ex.what());
        return 1;
    } catch (...) {
        set_error(err, err_len, "unknown OpenFHE scoring failure");
        return 1;
    }
}

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
) {
    try {
        if (initiator_ct == nullptr || initiator_ct_len == 0 ||
            candidate_ct_blob == nullptr || candidate_ct_lens == nullptr ||
            candidate_lat_q == nullptr || candidate_lon_q == nullptr || candidate_brownies == nullptr ||
            eval_mult_key == nullptr || eval_mult_key_len == 0 ||
            eval_sum_key == nullptr || eval_sum_key_len == 0 ||
            candidate_packages == nullptr || out_ct == nullptr || out_ct_len == nullptr) {
            set_error(err, err_len, "null pointer passed to ARESFullFusePayloadCKKS");
            return 1;
        }
        if (n_candidates <= 0 || profile_dim <= 0 || package_bytes <= 0 || payload_slot_count < package_bytes * 8) {
            set_error(err, err_len, "invalid full-fuse dimensions");
            return 1;
        }

        uint32_t batch_size = ring_dim >= 16 ? ring_dim / 2 : next_power_of_two(static_cast<uint32_t>(std::max(payload_slot_count, profile_dim)));
        if (batch_size < static_cast<uint32_t>(payload_slot_count)) {
            set_error(err, err_len, "contract batch size too small for payload slots");
            return 1;
        }
        auto cc = make_ckks_context(batch_size, depth == 0 ? 30 : depth, infer_scaling_mod_size(scaling_factor), 60);

        EvalKey<DCRTPoly> mult_key;
        {
            std::string raw(reinterpret_cast<const char*>(eval_mult_key), eval_mult_key_len);
            std::stringstream is(raw);
            Serial::Deserialize(mult_key, is, SerType::BINARY);
        }
        cc->InsertEvalMultKey({mult_key});
        std::map<usint, EvalKey<DCRTPoly>> sum_keys;
        {
            std::string raw(reinterpret_cast<const char*>(eval_sum_key), eval_sum_key_len);
            std::stringstream is(raw);
            Serial::Deserialize(sum_keys, is, SerType::BINARY);
        }
        cc->InsertEvalSumKey(std::make_shared<std::map<usint, EvalKey<DCRTPoly>>>(sum_keys));

        Ciphertext<DCRTPoly> init;
        {
            std::string raw(reinterpret_cast<const char*>(initiator_ct), initiator_ct_len);
            std::stringstream is(raw);
            Serial::Deserialize(init, is, SerType::BINARY);
        }
        std::vector<Ciphertext<DCRTPoly>> candidates;
        candidates.reserve(static_cast<size_t>(n_candidates));
        size_t offset = 0;
        for (int i = 0; i < n_candidates; i++) {
            size_t n = candidate_ct_lens[i];
            if (n == 0) {
                set_error(err, err_len, "candidate ciphertext length is zero");
                return 1;
            }
            Ciphertext<DCRTPoly> ct;
            std::string raw(reinterpret_cast<const char*>(candidate_ct_blob + offset), n);
            std::stringstream is(raw);
            Serial::Deserialize(ct, is, SerType::BINARY);
            candidates.push_back(ct);
            offset += n;
        }

        std::string comparator_value = comparator == nullptr ? "tanh_chebyshev" : std::string(comparator);
        if (comparator_value.empty()) {
            comparator_value = "tanh_chebyshev";
        }
        if (comparator_value != "tanh_chebyshev" && comparator_value != "logistic") {
            set_error(err, err_len, "full OpenFHE scorer supports tanh_chebyshev or logistic comparators");
            return 1;
        }
        if (comparator_degree <= 0) {
            comparator_degree = 27;
        }
        if (comparator_gain == 0.0) {
            comparator_gain = 100.0;
        }
        if (comparator_input_scale == 0.0) {
            comparator_input_scale = 0.5;
        }
        if (comparator_bound == 0.0) {
            comparator_bound = 0.5;
        }

        std::vector<Ciphertext<DCRTPoly>> ct_scores;
        ct_scores.reserve(static_cast<size_t>(n_candidates));
        for (int i = 0; i < n_candidates; i++) {
            auto prod = cc->EvalMult(init, candidates[i]);
            auto sim = cc->EvalSum(prod, profile_dim);
            sim = broadcast_first_slot(cc, sim, payload_slot_count, batch_size);
            double dlat = static_cast<double>(initiator_lat_q - candidate_lat_q[i]);
            double dlon = static_cast<double>(initiator_lon_q - candidate_lon_q[i]);
            double dist = dlat * dlat + dlon * dlon;
            auto score = cc->EvalMult(sim, beta / 2.0);
            score = cc->EvalAdd(score, (beta / 2.0) - alpha * dist + gamma * static_cast<double>(candidate_brownies[i]));
            ct_scores.push_back(score);
        }

        auto schedule = split_schedule(selector_schedule);
        std::vector<std::vector<Ciphertext<DCRTPoly>>> selectors(
            static_cast<size_t>(n_candidates),
            std::vector<Ciphertext<DCRTPoly>>(static_cast<size_t>(n_candidates))
        );
        for (int i = 0; i < n_candidates; i++) {
            selectors[i][i] = cc->EvalAdd(cc->EvalSub(ct_scores[i], ct_scores[i]), 1.0);
        }
        for (int i = 0; i < n_candidates; i++) {
            for (int j = i + 1; j < n_candidates; j++) {
                auto diff = cc->EvalSub(ct_scores[i], ct_scores[j]);
                Ciphertext<DCRTPoly> sel_ij;
                if (comparator_value == "logistic") {
                    sel_ij = eval_logistic_chebyshev(cc, diff, comparator_input_scale, comparator_gain, comparator_bound, comparator_degree);
                } else {
                    sel_ij = eval_tanh_chebyshev(cc, diff, comparator_input_scale, comparator_gain, comparator_bound, comparator_degree);
                }
                sel_ij = apply_selector_schedule(cc, sel_ij, schedule);
                auto one = cc->EvalAdd(cc->EvalSub(ct_scores[i], ct_scores[i]), 1.0);
                selectors[i][j] = sel_ij;
                selectors[j][i] = cc->EvalSub(one, sel_ij);
            }
        }

        Ciphertext<DCRTPoly> fused_payload;
        bool have_payload = false;
        for (int i = 0; i < n_candidates; i++) {
            std::vector<Ciphertext<DCRTPoly>> factors;
            factors.reserve(static_cast<size_t>(std::max(0, n_candidates - 1)));
            for (int j = 0; j < n_candidates; j++) {
                if (i != j) {
                    factors.push_back(selectors[i][j]);
                }
            }
            auto mask_ct = product_tree(cc, factors);
            auto bits = package_bits_for_candidate(candidate_packages, i, package_bytes, payload_slot_count, batch_size);
            auto bits_pt = cc->MakeCKKSPackedPlaintext(bits);
            auto weighted = cc->EvalMult(mask_ct, bits_pt);
            fused_payload = have_payload ? cc->EvalAdd(fused_payload, weighted) : weighted;
            have_payload = true;
        }
        if (!have_payload) {
            set_error(err, err_len, "full payload fusion produced no ciphertext");
            return 1;
        }
        if (serialize_object(fused_payload, out_ct, out_ct_len) != 0) {
            set_error(err, err_len, "serialize full fused payload failed");
            return 1;
        }
        return 0;
    } catch (const std::exception& ex) {
        set_error(err, err_len, ex.what());
        return 1;
    } catch (...) {
        set_error(err, err_len, "unknown OpenFHE full-fuse failure");
        return 1;
    }
}

} // extern "C"
