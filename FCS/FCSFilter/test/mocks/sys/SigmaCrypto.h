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

// SigmaCrypto.h
//
// FPGA-simulator-side implementation of the cryptographic primitives BKPS
// uses during the SIGMA provisioning handshake. BKPS treats whatever we
// return from the SDM mailbox as if it came from a real FPGA: it derives
// a shared secret via ECDH(bkpsPrivate, deviceDhPubKey), runs it through
// KdfProvider (HMAC-SHA384) to produce pmk/sek/smk, then verifies the MAC
// on SIGMA_M2 (HMAC-SHA384 with pmk) and SIGMA_ENC responses (AES-CTR
// decrypt with sek + HMAC-SHA256 with smk). Everything in this header
// reproduces those operations byte-for-byte on the C++ simulator side so
// BKPS can talk to us against no real board.
//
// See the Java references:
//   CryptoCore/.../sigma/SigmaProvider.java     (shared-secret derivation)
//   CryptoCore/.../sigma/KdfProvider.java       (pmk/sek/smk KDF)
//   CryptoCore/.../sigma/HMacSigmaProviderImpl  (HMAC-SHA384 for SIGMA_M2 MAC)
//   bkps/.../crypto/hmac/HMacSigmaEncProviderImpl.java (HMAC-SHA256 for ENC)
//   CommandCore/.../responses/sigma/SigmaM2MessageBuilder.java
//   CommandCore/.../responses/sigma/SigmaEncResponseBuilder.java

#ifndef FCS_MOCK_SIGMA_CRYPTO_H
#define FCS_MOCK_SIGMA_CRYPTO_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace fcsmock {

// P-384 public key is X||Y, each 48 bytes big-endian, uncompressed.
constexpr size_t P384_PUB_KEY_LEN = 96;
// P-384 private scalar (48 bytes big-endian) and X-coordinate shared secret.
constexpr size_t P384_COORD_LEN = 48;

// BKPS's KdfProvider output sizes. Do NOT change; they correspond to the
// KdfDetails enum entries in KdfProvider.java.
constexpr size_t PMK_LEN = 48;  // PROTOCOL MAC key -- feeds HMAC-SHA384 of M2
constexpr size_t SEK_LEN = 32;  // SESSION ENC key -- feeds AES-CTR for SIGMA_ENC
constexpr size_t SMK_LEN = 32;  // SESSION MAC key -- feeds HMAC-SHA256 for SIGMA_ENC

// A deterministic P-384 keypair used for the simulator "device" side. The
// private scalar is the constant 2, chosen so the public key is exactly 2*G
// (a valid curve point that is also non-generator, which BKPS's
// EcdhVerifier explicitly requires). Deterministic keys make debugging
// possible -- rerunning the simulator always produces the same M2 bytes
// for a given BKPS ephemeral key, so wire captures are reproducible.
struct DeviceKeyPair {
    // 48-byte big-endian scalar. For d=2 this is 0x00..02.
    std::array<uint8_t, P384_COORD_LEN> privateScalar;
    // X||Y public key point (2*G for d=2). Safe to publish; BKPS copies
    // it verbatim into sigmaM2Message.deviceDhPubKey and then runs ECDH
    // with its own private key, deriving the same shared secret we get
    // from (d * bkpsPub).
    std::array<uint8_t, P384_PUB_KEY_LEN> publicKeyXY;
};

// Returns a process-wide singleton simulator device keypair. Lazily
// generated on first call; thread-safe under C++11's static-local
// initialization guarantees. The returned reference is valid for the
// program lifetime.
const DeviceKeyPair& simulatorDeviceKey();

// Low-level primitives. All inputs and outputs are big-endian byte arrays
// matching BouncyCastle/JCE conventions (which is what BKPS uses through
// the BouncyCastleProvider).

// ECDH shared secret = x-coordinate of (devicePriv * bkpsPub) on P-384.
// devicePriv and bkpsPub sizes must equal P384_COORD_LEN and
// P384_PUB_KEY_LEN respectively. On success writes 48 big-endian bytes
// into `outSecret` and returns true. Returns false on any OpenSSL error
// or if `bkpsPub` is not a valid P-384 point.
bool ecdhP384(const uint8_t* devicePriv,
              const uint8_t* bkpsPubXY,
              uint8_t outSecret[P384_COORD_LEN]);

// HMAC-SHA384. Key length is arbitrary; output is always 48 bytes.
bool hmacSha384(const uint8_t* key, size_t keyLen,
                const uint8_t* data, size_t dataLen,
                uint8_t outMac[48]);

// HMAC-SHA256. Output is always 32 bytes.
bool hmacSha256(const uint8_t* key, size_t keyLen,
                const uint8_t* data, size_t dataLen,
                uint8_t outMac[32]);

// AES-CTR encrypt/decrypt (CTR is its own inverse). `key` must be 32 bytes
// (AES-256) because SEK_LEN is 32. `iv` must be 16 bytes. This wraps
// EVP_aes_256_ctr. Produces `outLen == inLen` bytes.
bool aesCtr256(const uint8_t* key,
               const uint8_t iv[16],
               const uint8_t* in, size_t inLen,
               uint8_t* out);

// Build BKPS's exact KDF input buffer for one of the three label/output
// combinations and run HMAC-SHA384 with the ECDH shared secret as key.
// Returns `outputLen` bytes of key material (48 for PMK, 32 for SEK/SMK).
//
// The layout, lifted verbatim from KdfProvider.getBuffer():
//   counter (4 LE, value 1)
//   label (27 bytes, ASCII, zero-padded on right)
//   separator (1 byte, 0x00)
//   context ("PSG-SIGMA", 16 bytes zero-padded)
//   reserved (4 LE, value 0)
//   outputKeySizeInBits (4 LE)
// Total: 56 bytes.  HMAC-SHA384 output is truncated to `outputLen`.
bool deriveSigmaKey(const uint8_t sharedSecret[P384_COORD_LEN],
                    const char* label,             // "PROTOCOL MAC" | "SESSION ENC" | "SESSION MAC"
                    size_t outputLen,              // 48 or 32
                    uint8_t* outKey);

// Convenience: derive all three keys at once from the ECDH shared secret.
struct SigmaSessionKeys {
    std::array<uint8_t, PMK_LEN> pmk;
    std::array<uint8_t, SEK_LEN> sek;
    std::array<uint8_t, SMK_LEN> smk;
};

bool deriveSigmaSessionKeys(const uint8_t sharedSecret[P384_COORD_LEN],
                            SigmaSessionKeys& outKeys);

// Opaque handle around an OpenSSL EC_KEY/EVP_PKEY loaded from a PKCS#8
// PEM file. The mock holds exactly one of these at any time (the
// fm_uds_bkp.key used to sign SIGMA M2); it is kept opaque so the header
// does not need to pull in openssl/evp.h.
struct EcPrivateKeyHandle;

// Load a P-384 private key from a PKCS#8 PEM file produced by
// robot/utils/attestation_cert_builder.py. Returns nullptr (and logs to
// stderr) on any failure: file missing, not PEM, not PKCS#8, not EC P-384.
// Ownership is transferred to the caller; release with freeEcPrivateKey.
EcPrivateKeyHandle* loadEcPrivateKey(const char* pemPath);

void freeEcPrivateKey(EcPrivateKeyHandle* key);

// ECDSA-P384 sign `data` with SHA-384 using the supplied private key.
// Writes R (48 BE bytes) to outR and S (48 BE bytes) to outS, matching
// BKPS's PsgSignatureBuilder layout (R/S are stored un-swapped inside
// the PSG signature block; only the leading magic/sizeR/sizeS/hashMagic
// ints are CONVERT). Returns false on any OpenSSL failure. Both outputs
// are padded with leading zeros if the natural encoding is shorter.
bool ecdsaP384SignRawRS(const EcPrivateKeyHandle* key,
                        const uint8_t* data, size_t dataLen,
                        uint8_t outR[48], uint8_t outS[48]);

} // namespace fcsmock

#endif // FCS_MOCK_SIGMA_CRYPTO_H
