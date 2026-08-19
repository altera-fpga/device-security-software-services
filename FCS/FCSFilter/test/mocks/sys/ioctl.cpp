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

#include "ioctl.h"
#include "fcntl.h"
#include "Logger.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <vector>

#include "FcsSimulator.h"

#ifdef SPDM_SIM
#include "SigmaCrypto.h"
#include "spdmSimulator.h"
#endif

namespace {

// Hex helpers ---------------------------------------------------------------

bool nibble(char c, uint8_t& n) {
    if (c >= '0' && c <= '9') { n = c - '0';      return true; }
    if (c >= 'a' && c <= 'f') { n = c - 'a' + 10; return true; }
    if (c >= 'A' && c <= 'F') { n = c - 'A' + 10; return true; }
    return false;
}

bool decodeHex(const std::string& s, std::vector<uint8_t>& out) {
    std::string t;
    t.reserve(s.size());
    for (char c : s) {
        if (!isspace(static_cast<unsigned char>(c))) t.push_back(c);
    }

    // 2. Remove any "0x" or "0X" prefix (if present)
    if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        t.erase(0, 2);
    }
    if (t.empty() || (t.size() % 2) != 0) return false;
    out.clear();
    out.reserve(t.size() / 2);
    for (size_t i = 0; i < t.size(); i += 2) {
        uint8_t hi, lo;
        if (!nibble(t[i], hi) || !nibble(t[i + 1], lo)) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string slurpFile(const char* path) {
    std::ifstream f(path);
    if (!f.is_open()) return {};
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// chipId override -----------------------------------------------------------
// Read 16-hex-char file and serve via GET_CHIPID + SIGMA M2 deviceUniqueId.

const char* const kChipIdFiles[] = {
    "./spdmSim1.2/chipid.txt",
    "./spdmSim1.5/chipid.txt"
};

constexpr const char* kDefaultChipIdHex = "1234567890abcdef";

uint8_t* loadChipIdOnce() {
    static uint8_t g_chipIdBE[8] = {0};

    for (const char* const* p = kChipIdFiles; *p; ++p) {
        std::vector<uint8_t> bytes;
        if (decodeHex(slurpFile(*p), bytes) && bytes.size() == 8) {
            std::memcpy(g_chipIdBE, bytes.data(), 8);
            Logger::log(std::string("Loaded chipId from ") + *p, Debug);
            return g_chipIdBE;
        }
    }
    std::vector<uint8_t> bytes;
    if (decodeHex(kDefaultChipIdHex, bytes) && bytes.size() == 8) {
        std::memcpy(g_chipIdBE, bytes.data(), 8);
    }
    Logger::log("No chipId file found; using compiled-in default", Debug);

    return g_chipIdBE;
}

#ifdef SPDM_SIM

// SigmaM2MessageBuilder parses publicEfuseValues with CONVERT (32-bit BE on
// wire -> LE logical). Service cfg value hex matches logical byte order, so
// each 32-bit word from efuse.hex must be byte-reversed on the wire.
// SPDM_SIM-only: only referenced from buildSigmaM2.
void copyPublicEfuseToWire(uint8_t* dst, const uint8_t* src, size_t nbytes) {
    size_t i = 0;
    for (; i + 4 <= nbytes; i += 4) {
        dst[i]     = src[i + 3];
        dst[i + 1] = src[i + 2];
        dst[i + 2] = src[i + 1];
        dst[i + 3] = src[i];
    }
    for (; i < nbytes; ++i) dst[i] = src[i];
}

// publicEfuseValues override -----------------------------------------------
// BKPS check: applyMask(m2.publicEfuseValues, cfg.mask) == cfg.value.
// Robot writes cfg.value (already mask-aligned) to efuse.hex, so copying
// the bytes verbatim into the M2 field passes verification.

const char* const kEfuseFiles[] = {
    "./spdmSim1.2/efuse.hex"
};

std::vector<uint8_t> loadEfuseOnce() {
    std::vector<uint8_t>  g_efuseBytes;

    for (const char* const* p = kEfuseFiles; *p; ++p) {
        std::vector<uint8_t> tmp;
        if (decodeHex(slurpFile(*p), tmp)) {
            g_efuseBytes = std::move(tmp);
            Logger::log(std::string("Loaded efuse bytes from ") + *p +
                        " (" + std::to_string(g_efuseBytes.size()) + ")", Debug);
            break;
        }
    }
    Logger::log("No efuse file found; M2 publicEfuseValues stays zero", Debug);
    return g_efuseBytes;
}

// uds_bkp.key (signs SIGMA M2) ------------------------------------------

const char* const kUdsBkpKeyFiles[] = {
    "./spdmSim1.2/certs/uds_bkp.key",
};

std::mutex                    g_KeyMutex;
fcsmock::EcPrivateKeyHandle*  g_Key       = nullptr;
bool                          g_KeyTried  = false;

fcsmock::EcPrivateKeyHandle* getUdsBkpKey() {
    std::lock_guard<std::mutex> lk(g_KeyMutex);
    if (g_Key || g_KeyTried) return g_Key;
    g_KeyTried = true;

    for (const char* const* p = kUdsBkpKeyFiles; *p; ++p) {
        g_Key = fcsmock::loadEcPrivateKey(*p);
        if (g_Key) {
            Logger::log(std::string("Loaded uds_bkp.key from ") + *p, Debug);
            return g_Key;
        }
    }
    Logger::log("uds_bkp.key not found; M2 signature will be zero", Error);
    return nullptr;
}

// idCode override -----------------------------------------------------------
// Read 8-hex-char file (4 bytes, big-endian human form) and serve via
// GET_IDCODE.
const char* const kIdCodeFiles[] = {
    "./spdmSim1.2/idcode.txt",
    "./spdmSim1.5/idcode.txt"
};
constexpr uint32_t kDefaultIdCode = 0x6341D0DDu;  // Agilex (family 0x34)

uint32_t loadIdCodeOnce() {
    for (const char* const* p = kIdCodeFiles; *p; ++p) {
        std::vector<uint8_t> bytes;
        if (decodeHex(slurpFile(*p), bytes) && bytes.size() == 4) {
            Logger::log(std::string("Loaded idcode from ") + *p, Debug);
            return (static_cast<uint32_t>(bytes[0]) << 24)
                 | (static_cast<uint32_t>(bytes[1]) << 16)
                 | (static_cast<uint32_t>(bytes[2]) <<  8)
                 |  static_cast<uint32_t>(bytes[3]);
        }
    }
    Logger::log("No idcode file found; using compiled-in default", Debug);
    return kDefaultIdCode;
}

// SDM mailbox command codes (subset).
constexpr uint16_t MBOX_SIGMA_M1  = 0xD2;
constexpr uint16_t MBOX_SIGMA_M3  = 0xD3;
constexpr uint16_t MBOX_SIGMA_ENC = 0xD4;

uint8_t idcodeFamilyId(uint32_t idcode) {
    return static_cast<uint8_t>((idcode >> 20) & 0xFFu);
}

// Per-family M2 shape (DeviceFamilyFuseMap.java).
struct M2Profile { uint8_t fuseMapOrdinal; size_t efuseLen; };

M2Profile profileFor(uint8_t familyId) {
    if (familyId == 0x32) return {0x00, 256};   // S10
    return {0x01, 1024};                         // FM568 (Agilex/AgilexB/n5x)
}

// SIGMA_M1 layout: [reservedHeader 4][magic 4][reserved1 4][bkpsDhPubKey 96]...
constexpr size_t M1_BKPS_PUB_OFF = 12;
constexpr size_t DH_PUB_LEN      = 96;

// Build a structurally-valid SIGMA_M2 with valid PSG sig (R||S over the
// magic..bkpsDhPubKey range) and valid HMAC-SHA384 over magic..signature.
std::vector<uint8_t> buildSigmaM2(uint8_t familyId,
                                  const std::vector<uint8_t>& m1) {
    const M2Profile p = profileFor(familyId);

    const size_t OFF_MAGIC          = 4;
    const size_t OFF_SDM_SESSION_ID = OFF_MAGIC + 4;
    const size_t OFF_DEVICE_UID     = OFF_SDM_SESSION_ID + 4;
    const size_t OFF_FAMILY_FUSEMAP = OFF_DEVICE_UID + 8 + 4 + 28 + 4;
    const size_t OFF_PUB_EFUSES     = OFF_FAMILY_FUSEMAP + 1 + 3;
    const size_t OFF_DEVICE_DH_PUB  = OFF_PUB_EFUSES + p.efuseLen;
    const size_t OFF_BKPS_DH_PUB    = OFF_DEVICE_DH_PUB + DH_PUB_LEN;
    const size_t OFF_PSG_SIG        = OFF_BKPS_DH_PUB + DH_PUB_LEN;
    const size_t OFF_MAC            = OFF_PSG_SIG + 112;
    const size_t TOTAL              = OFF_MAC + 48;

    std::vector<uint8_t> m2(TOTAL, 0);

    auto put_be32 = [&](size_t off, uint32_t v) {
        m2[off + 0] = (v >> 24) & 0xFF; m2[off + 1] = (v >> 16) & 0xFF;
        m2[off + 2] = (v >>  8) & 0xFF; m2[off + 3] = (v      ) & 0xFF;
    };
    // PSG signature header is read big-endian then byte-swapped (CONVERT
    // tagged); writing little-endian on the wire yields the right value.
    auto put_le32 = [&](size_t off, uint32_t v) {
        m2[off + 0] = (v      ) & 0xFF; m2[off + 1] = (v >>  8) & 0xFF;
        m2[off + 2] = (v >> 16) & 0xFF; m2[off + 3] = (v >> 24) & 0xFF;
    };

    put_be32(OFF_MAGIC, 0xFC06A385u);
    put_be32(OFF_SDM_SESSION_ID, 0x00000001u);

    uint8_t* g_chipIdBE = loadChipIdOnce();
    std::memcpy(&m2[OFF_DEVICE_UID], g_chipIdBE, 8);

    m2[OFF_FAMILY_FUSEMAP] = p.fuseMapOrdinal;

    std::vector<uint8_t> g_efuseBytes = loadEfuseOnce();
    if (!g_efuseBytes.empty()) {
        const size_t n = std::min(g_efuseBytes.size(), p.efuseLen);
        copyPublicEfuseToWire(&m2[OFF_PUB_EFUSES], g_efuseBytes.data(), n);
    }

    // deviceDhPubKey = 2*G (d=2 known to us so we can ECDH-match BKPS).
    const auto& devKey = fcsmock::simulatorDeviceKey();
    std::copy(devKey.publicKeyXY.begin(), devKey.publicKeyXY.end(),
              m2.begin() + OFF_DEVICE_DH_PUB);

    // Echo BKPS's pub key from M1 (or leave zero if M1 is truncated).
    const bool m1HasPub = m1.size() >= M1_BKPS_PUB_OFF + DH_PUB_LEN;
    if (m1HasPub) {
        std::copy(m1.begin() + M1_BKPS_PUB_OFF,
                  m1.begin() + M1_BKPS_PUB_OFF + DH_PUB_LEN,
                  m2.begin() + OFF_BKPS_DH_PUB);
    }

    // PSG signature header: STANDARD magic, sizeR/S=48, SECP384R1.
    put_le32(OFF_PSG_SIG +  0, 0x74881520u);
    put_le32(OFF_PSG_SIG +  4, 48u);
    put_le32(OFF_PSG_SIG +  8, 48u);
    put_le32(OFF_PSG_SIG + 12, 0x30548820u);

    // ECDSA-P384 sign (magic..bkpsDhPubKey).
    if (auto* key = getUdsBkpKey()) {
        uint8_t r[48] = {0}, s[48] = {0};
        if (fcsmock::ecdsaP384SignRawRS(key,
                                        m2.data() + OFF_MAGIC,
                                        OFF_PSG_SIG - OFF_MAGIC,
                                        r, s)) {
            std::memcpy(&m2[OFF_PSG_SIG + 16],      r, 48);
            std::memcpy(&m2[OFF_PSG_SIG + 16 + 48], s, 48);
        } else {
            Logger::log("ECDSA sign of M2 failed; R/S left zero", Error);
        }
    }

    if (!m1HasPub) {
        Logger::log("SIGMA_M1 too short; MAC left zero", Error);
        return m2;
    }

    // pmk = KDF(ECDH(d=2, bkpsPub)); mac = HMAC-SHA384(pmk, magic..signature).
    uint8_t shared[fcsmock::P384_COORD_LEN] = {0};
    if (!fcsmock::ecdhP384(devKey.privateScalar.data(),
                           m1.data() + M1_BKPS_PUB_OFF, shared)) {
        Logger::log("ECDH failed; MAC left zero", Error);
        return m2;
    }

    fcsmock::SigmaSessionKeys keys{};
    if (!fcsmock::deriveSigmaSessionKeys(shared, keys)) {
        Logger::log("KDF failed; MAC left zero", Error);
        return m2;
    }

    uint8_t mac[48] = {0};
    if (!fcsmock::hmacSha384(keys.pmk.data(), keys.pmk.size(),
                             m2.data() + OFF_MAGIC, OFF_MAC - OFF_MAGIC,
                             mac)) {
        Logger::log("HMAC-SHA384 failed; MAC left zero", Error);
        return m2;
    }
    std::memcpy(&m2[OFF_MAC], mac, 48);

    return m2;
}
#endif // SPDM_SIM

} // namespace

int ioctl(int fileDescriptor, unsigned long int commandCode, altera_fcs_dev_ioctl *data) {
    Logger::log("ioctl() mock called", Debug);
    if (data == nullptr) {
        errno = EFAULT;
        return -1;
    }
    if (fileDescriptor != MOCK_FILE_DESCRIPTOR) {
        errno = EBADF;
        return -1;
    }
    switch (commandCode) {
        case (ALTERA_FCS_DEV_CHIP_ID_CMD): {
            uint8_t* g_chipIdBE = loadChipIdOnce();
            uint32_t low = 0, high = 0;
            for (int i = 0; i < 4; ++i) {
                low  |= static_cast<uint32_t>(g_chipIdBE[i])     << (8 * i);
                high |= static_cast<uint32_t>(g_chipIdBE[i + 4]) << (8 * i);
            }
            data->com_paras.c_id.chip_id_low  = low;
            data->com_paras.c_id.chip_id_high = high;
            data->status = 0;
        }
        break;
        case (ALTERA_FCS_DEV_PSGSIGMA_TEARDOWN_CMD): {
            Logger::log("SIGMA_TEARDOWN mock: sid=" +
                        std::to_string(data->com_paras.tdown.sid), Debug);
#ifdef SPDM_SIM
            // SPDM_SIM runtime (Robot tests): accept any sid, including
            // 0xFFFFFFFF "all sessions". BKPS issues teardown with arbitrary
            // session ids during onboarding and expects success.
            data->status = 0;
#else
            // gtest semantics: only the sid matching expectedSessionId is
            // accepted; anything else returns -1.
            data->status = (data->com_paras.tdown.sid == FcsSimulator::expectedSessionId)
                    ? 0
                    : -1;
#endif
        }
        break;
        case (ALTERA_FCS_DEV_ATTESTATION_SUBKEY_CMD): {
            if (data->com_paras.subkey.rsp_data_sz < ATTESTATION_SUBKEY_RSP_MAX_SZ) {
                errno = EINVAL;
                return -1;
            }
            if (data->com_paras.subkey.cmd_data_sz != FcsSimulator::expectedCreateSubkeyCommandLength) {
                data->status = -1;
            } else {
                std::vector<uint8_t> buffer(ATTESTATION_SUBKEY_RSP_MAX_SZ, 0x7E);
                std::copy(buffer.begin(), buffer.end(), data->com_paras.subkey.rsp_data);
                data->com_paras.subkey.rsp_data_sz = buffer.size();
                data->status = 0;
            }
        }
        break;
        case (ALTERA_FCS_DEV_ATTESTATION_MEASUREMENT_CMD): {
            if (data->com_paras.measurement.rsp_data_sz < ATTESTATION_MEASUREMENT_RSP_MAX_SZ) {
                errno = EINVAL;
                return -1;
            }
            if (data->com_paras.measurement.cmd_data_sz != FcsSimulator::expectedGetMeasurementCommandLength) {
                data->status = -1;
            }
            std::vector<uint8_t> buffer(FcsSimulator::expectedGetMeasurementResponseLength, 0x7E);
            std::copy(buffer.begin(), buffer.end(), data->com_paras.subkey.rsp_data);
            data->com_paras.measurement.rsp_data_sz = buffer.size();
            data->status = 0;
        }
        break;
#ifdef SPDM_SIM
        case (ALTERA_FCS_DEV_ATTESTATION_GET_CERTIFICATE): {
            std::vector<uint8_t> outputBuffer;
            int status = SpdmSimulator::sendGetAttestationCommand(data->com_paras.certificate.c_request, outputBuffer);
            Logger::logWithReturnCode("SpdmSimulator::sendGetAttestationCommand called", status, Debug);
            std::copy(outputBuffer.begin(), outputBuffer.end(), static_cast<char*>(data->com_paras.certificate.rsp_data));
            data->com_paras.certificate.rsp_data_sz = outputBuffer.size();
            data->status = 0;
        }
        break;
        case (ALTERA_FCS_DEV_MBOX_SEND): {
            std::vector<uint8_t> inputBuffer;
            uint8_t* dataPtr = static_cast<uint8_t*>(data->com_paras.mbox_send_cmd.cmd_data);
            inputBuffer.assign(dataPtr, dataPtr + data->com_paras.mbox_send_cmd.cmd_data_sz);

            switch (data->com_paras.mbox_send_cmd.mbox_cmd) {
                case (GET_IDCODE): {
                    Logger::log("SpdmSimulator::getIdCode called", Debug);
                    uint32_t idCode = loadIdCodeOnce();
                    std::memcpy(data->com_paras.mbox_send_cmd.rsp_data, &idCode, 4);
                    data->com_paras.mbox_send_cmd.rsp_data_sz = 4;
                    data->status = 0;
                }
                break;
                case (MBOX_SIGMA_M1): {
                    const uint8_t fid = idcodeFamilyId(loadIdCodeOnce());
                    char famLog[64];
                    std::snprintf(famLog, sizeof(famLog),
                                  "SIGMA_M1 -> SIGMA_M2 (family=0x%02x)", (unsigned)fid);
                    Logger::log(std::string(famLog), Debug);
                    const auto m2 = buildSigmaM2(fid, inputBuffer);
                    std::copy(m2.begin(), m2.end(),
                              static_cast<uint8_t*>(data->com_paras.mbox_send_cmd.rsp_data));
                    data->com_paras.mbox_send_cmd.rsp_data_sz = m2.size();
                    data->status = 0;
                }
                break;
                case (MBOX_SIGMA_M3): {
                    Logger::log("SIGMA_M3 -> empty SIGMA_M4 ack", Debug);
                    data->com_paras.mbox_send_cmd.rsp_data_sz = 0;
                    data->status = 0;
                }
                break;
                case (MBOX_SIGMA_ENC): {
                    // Empty payload -> BKPS uses HEADER_ONLY flow, skips
                    // integrity/decrypt verification.
                    Logger::log("SIGMA_ENC -> empty (HEADER_ONLY)", Debug);
                    data->com_paras.mbox_send_cmd.rsp_data_sz = 0;
                    data->status = 0;
                }
                break;
                default: {
                    std::vector<uint8_t> outputBuffer;
                    Logger::log("SpdmSimulator::sendCommand called", Debug);
                    int status = SpdmSimulator::sendCommand(data->com_paras.mbox_send_cmd.mbox_cmd, inputBuffer, outputBuffer);
                    Logger::logWithReturnCode("SpdmSimulator::sendCommand", status, Debug);
                    std::copy(outputBuffer.begin(), outputBuffer.end(), static_cast<uint8_t*>(data->com_paras.mbox_send_cmd.rsp_data));
                    data->com_paras.mbox_send_cmd.rsp_data_sz = outputBuffer.size();
                    data->status = 0;
                }
                break;
            }
        }
        break;
#else
        case (ALTERA_FCS_DEV_ATTESTATION_GET_CERTIFICATE): {
            if (data->com_paras.certificate.rsp_data_sz < ATTESTATION_CERTIFICATE_RSP_MAX_SZ) {
                errno = EINVAL;
                return -1;
            }
            if (data->com_paras.certificate.c_request != (int) FcsSimulator::expectedCertificateRequest) {
                data->status = -1;
            }
            std::vector<uint8_t> buffer(FcsSimulator::expectedGetAttCertResponseLength, 0x7E);
            std::copy(buffer.begin(), buffer.end(), data->com_paras.certificate.rsp_data);
            data->com_paras.certificate.rsp_data_sz = buffer.size();
            data->status = 0;
        }
        break;
#endif
        default: {
            errno = EINVAL;
            return -1;
        }
        break;
    }
    return 0;
}
