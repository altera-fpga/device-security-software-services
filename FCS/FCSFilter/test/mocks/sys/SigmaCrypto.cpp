/*
This project, FPGA Crypto Service Server, is licensed as below

***************************************************************************

Copyright 2020-2025 Altera Corporation. All Rights Reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

***************************************************************************
*/

#include "SigmaCrypto.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

namespace fcsmock {

namespace {

// Copy the low bytes of a BIGNUM into `out`, left-padded with zeros so the
// result is exactly `len` bytes. BN_bn2binpad is OpenSSL 1.1.0+, which the
// repo's dependency set provides (OpenSSL 3.1.4).
bool bnToFixed(const BIGNUM* bn, uint8_t* out, size_t len) {
    if (!bn) return false;
    const int written = BN_bn2binpad(bn, out, static_cast<int>(len));
    return written == static_cast<int>(len);
}

// Build a little-endian 4-byte value at `out`.
inline void putLe32(uint8_t* out, uint32_t v) {
    out[0] = static_cast<uint8_t>((v >> 0) & 0xFF);
    out[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    out[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    out[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

// Encode `src` (exactly `len` bytes) at `out[offset..offset+len)` and
// zero-pad any remaining slot up to `slotLen`.
void encodeFixedField(uint8_t* out, size_t slotLen, const char* src, size_t srcLen) {
    std::memset(out, 0, slotLen);
    std::memcpy(out, src, srcLen > slotLen ? slotLen : srcLen);
}

// Compute 2*G on P-384 and export as uncompressed X||Y. Used once at
// singleton init time to guarantee the device public key we advertise in
// SIGMA_M2 exactly matches what OpenSSL will derive when BKPS asks us
// (indirectly) to run ECDH with its private key. Returns false on any
// OpenSSL failure.
bool computeDevicePubKey2G(uint8_t outXY[P384_PUB_KEY_LEN]) {
    bool ok = false;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_POINT* pub   = nullptr;
    BIGNUM*   two   = nullptr;
    BIGNUM*   x     = nullptr;
    BIGNUM*   y     = nullptr;
    BN_CTX*   ctx   = BN_CTX_new();
    if (!group || !ctx) goto cleanup;

    pub = EC_POINT_new(group);
    two = BN_new();
    x   = BN_new();
    y   = BN_new();
    if (!pub || !two || !x || !y) goto cleanup;

    if (!BN_set_word(two, 2)) goto cleanup;
    // pub = 2 * G (generator multiplication; 2nd arg is scalar for G).
    if (!EC_POINT_mul(group, pub, two, nullptr, nullptr, ctx)) goto cleanup;
    if (!EC_POINT_get_affine_coordinates(group, pub, x, y, ctx)) goto cleanup;

    if (!bnToFixed(x, outXY, P384_COORD_LEN)) goto cleanup;
    if (!bnToFixed(y, outXY + P384_COORD_LEN, P384_COORD_LEN)) goto cleanup;
    ok = true;

cleanup:
    if (pub)   EC_POINT_free(pub);
    if (two)   BN_free(two);
    if (x)     BN_free(x);
    if (y)     BN_free(y);
    if (ctx)   BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    return ok;
}

} // namespace

const DeviceKeyPair& simulatorDeviceKey() {
    // C++11 static-local: initialised once, thread-safe.
    static DeviceKeyPair instance = [] {
        DeviceKeyPair kp{};
        // Private scalar d = 2 (48-byte big-endian: 0x00..0x00 0x02).
        kp.privateScalar.fill(0);
        kp.privateScalar[P384_COORD_LEN - 1] = 0x02;

        if (!computeDevicePubKey2G(kp.publicKeyXY.data())) {
            // Last-ditch: leave publicKeyXY zeroed. Subsequent ECDH in
            // the caller will fail loudly. We avoid aborting the process
            // because the simulator is used in tests that we'd rather
            // have produce a clean error than a coredump.
            kp.publicKeyXY.fill(0);
        }
        return kp;
    }();
    return instance;
}

bool ecdhP384(const uint8_t* devicePriv,
              const uint8_t* bkpsPubXY,
              uint8_t outSecret[P384_COORD_LEN]) {
    bool ok = false;
    EC_GROUP* group   = EC_GROUP_new_by_curve_name(NID_secp384r1);
    EC_POINT* pubPt   = nullptr;
    EC_POINT* secret  = nullptr;
    BIGNUM*   priv    = nullptr;
    BIGNUM*   pubX    = nullptr;
    BIGNUM*   pubY    = nullptr;
    BIGNUM*   sx      = nullptr;
    BIGNUM*   sy      = nullptr;
    BN_CTX*   ctx     = BN_CTX_new();
    if (!group || !ctx) goto cleanup;

    pubPt  = EC_POINT_new(group);
    secret = EC_POINT_new(group);
    priv   = BN_bin2bn(devicePriv, P384_COORD_LEN, nullptr);
    pubX   = BN_bin2bn(bkpsPubXY, P384_COORD_LEN, nullptr);
    pubY   = BN_bin2bn(bkpsPubXY + P384_COORD_LEN, P384_COORD_LEN, nullptr);
    sx     = BN_new();
    sy     = BN_new();
    if (!pubPt || !secret || !priv || !pubX || !pubY || !sx || !sy) goto cleanup;

    // Build bkpsPub as an EC_POINT and validate it lies on the curve.
    if (!EC_POINT_set_affine_coordinates(group, pubPt, pubX, pubY, ctx)) goto cleanup;
    if (EC_POINT_is_on_curve(group, pubPt, ctx) != 1) goto cleanup;

    // secret = priv * pubPt
    if (!EC_POINT_mul(group, secret, nullptr, pubPt, priv, ctx)) goto cleanup;
    if (EC_POINT_is_at_infinity(group, secret)) goto cleanup;

    // Shared secret is the X-coordinate of `secret`, big-endian 48 bytes.
    // This matches the convention used by BouncyCastle / ECDH-with-JCE on
    // the BKPS side, which in turn matches what KdfProvider consumes.
    if (!EC_POINT_get_affine_coordinates(group, secret, sx, sy, ctx)) goto cleanup;
    if (!bnToFixed(sx, outSecret, P384_COORD_LEN)) goto cleanup;
    ok = true;

cleanup:
    if (pubPt)  EC_POINT_free(pubPt);
    if (secret) EC_POINT_free(secret);
    if (priv)   BN_clear_free(priv);
    if (pubX)   BN_free(pubX);
    if (pubY)   BN_free(pubY);
    if (sx)     BN_clear_free(sx);
    if (sy)     BN_free(sy);
    if (ctx)    BN_CTX_free(ctx);
    if (group)  EC_GROUP_free(group);
    return ok;
}

static bool hmacGeneric(const EVP_MD* md,
                        const uint8_t* key, size_t keyLen,
                        const uint8_t* data, size_t dataLen,
                        uint8_t* outMac, unsigned int expectedLen) {
    unsigned int outLen = 0;
    unsigned char* ret = HMAC(md,
                              key, static_cast<int>(keyLen),
                              data, dataLen,
                              outMac, &outLen);
    return ret != nullptr && outLen == expectedLen;
}

bool hmacSha384(const uint8_t* key, size_t keyLen,
                const uint8_t* data, size_t dataLen,
                uint8_t outMac[48]) {
    return hmacGeneric(EVP_sha384(), key, keyLen, data, dataLen, outMac, 48);
}

bool hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* data, size_t dataLen,
                uint8_t outMac[32]) {
    return hmacGeneric(EVP_sha256(), key, keyLen, data, dataLen, outMac, 32);
}

bool aesCtr256(const uint8_t* key,
               const uint8_t iv[16],
               const uint8_t* in, size_t inLen,
               uint8_t* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int outLen1 = 0, outLen2 = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) goto cleanup;
    if (EVP_EncryptUpdate(ctx, out, &outLen1,
                          in, static_cast<int>(inLen)) != 1) goto cleanup;
    if (EVP_EncryptFinal_ex(ctx, out + outLen1, &outLen2) != 1) goto cleanup;
    ok = (static_cast<size_t>(outLen1 + outLen2) == inLen);

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// Reproduces KdfProvider.getBuffer() byte-for-byte, then HMAC-SHA384s it
// with the ECDH shared secret as key. The result is truncated to `outputLen`
// (48 for PMK, 32 for SEK/SMK), matching the Arrays.copyOfRange() in
// KdfProvider.deriveInternal.
bool deriveSigmaKey(const uint8_t sharedSecret[P384_COORD_LEN],
                    const char* label,
                    size_t outputLen,
                    uint8_t* outKey) {
    if (!label || !outKey) return false;
    if (outputLen == 0 || outputLen > 48) return false;

    // Layout (all sizes match KdfProvider.java constants):
    //   4  counter       little-endian, value 1
    //  27  label         ASCII, zero-padded on right to LABEL_LEN
    //   1  separator     0x00
    //  16  context       "PSG-SIGMA" zero-padded on right to CONTEXT_LEN
    //   4  reserved      little-endian, value 0
    //   4  outputBits    little-endian, value outputLen * 8
    // total = 56
    constexpr size_t COUNTER_LEN = 4;
    constexpr size_t LABEL_LEN   = 27;
    constexpr size_t SEPARATOR_LEN = 1;
    constexpr size_t CONTEXT_LEN = 16;
    constexpr size_t RESERVED_LEN = 4;
    constexpr size_t OUTPUT_KEY_SIZE_LEN = 4;
    constexpr size_t TOTAL =
        COUNTER_LEN + LABEL_LEN + SEPARATOR_LEN + CONTEXT_LEN + RESERVED_LEN + OUTPUT_KEY_SIZE_LEN;

    uint8_t buf[TOTAL];
    std::memset(buf, 0, TOTAL);

    size_t pos = 0;
    putLe32(buf + pos, 1);                     pos += COUNTER_LEN;
    encodeFixedField(buf + pos, LABEL_LEN,
                     label, std::strlen(label)); pos += LABEL_LEN;
    buf[pos] = 0;                              pos += SEPARATOR_LEN;
    encodeFixedField(buf + pos, CONTEXT_LEN,
                     "PSG-SIGMA",
                     std::strlen("PSG-SIGMA")); pos += CONTEXT_LEN;
    putLe32(buf + pos, 0);                     pos += RESERVED_LEN;
    putLe32(buf + pos,
            static_cast<uint32_t>(outputLen * 8)); pos += OUTPUT_KEY_SIZE_LEN;
    (void)pos;

    uint8_t fullMac[48];
    if (!hmacSha384(sharedSecret, P384_COORD_LEN,
                    buf, TOTAL, fullMac)) {
        return false;
    }
    std::memcpy(outKey, fullMac, outputLen);
    return true;
}

bool deriveSigmaSessionKeys(const uint8_t sharedSecret[P384_COORD_LEN],
                            SigmaSessionKeys& outKeys) {
    if (!deriveSigmaKey(sharedSecret, "PROTOCOL MAC", PMK_LEN, outKeys.pmk.data())) return false;
    if (!deriveSigmaKey(sharedSecret, "SESSION ENC",  SEK_LEN, outKeys.sek.data())) return false;
    if (!deriveSigmaKey(sharedSecret, "SESSION MAC",  SMK_LEN, outKeys.smk.data())) return false;
    return true;
}

// --- EC private key loading + ECDSA signing ------------------------------
//
// Used to sign the SIGMA_M2 getDataForSignature() byte range with
// fm_uds_bkp.key. The loaded key's public counterpart must be the leaf
// of the DICE chain BKPS will validate (fm_uds_bkp.cer); otherwise
// SigmaM2SignatureVerifier will reject the signature even if it is a
// valid ECDSA signature under some other key.

struct EcPrivateKeyHandle {
    EVP_PKEY* pkey;
};

EcPrivateKeyHandle* loadEcPrivateKey(const char* pemPath) {
    if (!pemPath) return nullptr;
    FILE* fp = std::fopen(pemPath, "rb");
    if (!fp) {
        std::fprintf(stderr, "SigmaCrypto: cannot open %s\n", pemPath);
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    std::fclose(fp);
    if (!pkey) {
        std::fprintf(stderr, "SigmaCrypto: PEM_read_PrivateKey failed for %s\n", pemPath);
        return nullptr;
    }
    // Sanity check: must be P-384 EC. BKPS's SigmaM2SignatureVerifier
    // picks EcSignatureAlgorithm from the public key's curve spec; a
    // mismatched curve triggers "Sigma M2 signature verification failed".
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        std::fprintf(stderr, "SigmaCrypto: %s is not an EC key\n", pemPath);
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    auto* h = new EcPrivateKeyHandle{pkey};
    return h;
}

void freeEcPrivateKey(EcPrivateKeyHandle* key) {
    if (!key) return;
    if (key->pkey) EVP_PKEY_free(key->pkey);
    delete key;
}

bool ecdsaP384SignRawRS(const EcPrivateKeyHandle* key,
                        const uint8_t* data, size_t dataLen,
                        uint8_t outR[48], uint8_t outS[48]) {
    if (!key || !key->pkey || !data || !outR || !outS) return false;

    // EVP_DigestSign handles SHA-384 + ECDSA atomically. It emits a
    // DER-encoded SEQUENCE { INTEGER r, INTEGER s }, which we then
    // decode to extract raw R||S for PsgSignatureBuilder.
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;

    bool ok = false;
    std::vector<uint8_t> derSig;
    do {
        if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha384(), nullptr, key->pkey) != 1) break;
        if (EVP_DigestSignUpdate(mdctx, data, dataLen) != 1) break;

        size_t sigLen = 0;
        if (EVP_DigestSignFinal(mdctx, nullptr, &sigLen) != 1) break;
        derSig.resize(sigLen);
        if (EVP_DigestSignFinal(mdctx, derSig.data(), &sigLen) != 1) break;
        derSig.resize(sigLen);

        const uint8_t* p = derSig.data();
        ECDSA_SIG* ecSig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(derSig.size()));
        if (!ecSig) break;

        const BIGNUM* r = nullptr;
        const BIGNUM* s = nullptr;
        ECDSA_SIG_get0(ecSig, &r, &s);
        const bool wrote =
            bnToFixed(r, outR, 48) &&
            bnToFixed(s, outS, 48);
        ECDSA_SIG_free(ecSig);
        if (!wrote) break;

        ok = true;
    } while (false);

    EVP_MD_CTX_free(mdctx);
    return ok;
}

} // namespace fcsmock
