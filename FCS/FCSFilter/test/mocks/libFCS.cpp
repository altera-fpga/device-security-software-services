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

// libFCS.so simulator implementation.
//
// On a real Agilex/AgilexB platform `libFCS.so` is the user-space FCS shim
// that bkp_app dlopen()s (FcsCommunicationFcsLib.cpp). Every FPGA-side
// command except the local QSPI helpers ultimately travels over MCTP/SPDM
// to the SDM. This file is the simulator counterpart of that library: it
// exports the same ABI but services every call through the in-tree SPDM
// simulator (libfirmware_spdm_sim.so via SpdmSimulator) so AgilexB's
// SPDM/KEY_EX provisioning can be exercised end-to-end without real
// hardware and without the legacy ioctl/SIGMA mock path.
//
// The Robot test suites already stage the per-device chip id, idcode and
// attestation cert chain (manifestfiller artifacts) under
// ${SPDM_SIM_OUTPUT_DIR}/{chipid.txt, idcode.txt, certs/}. This library
// reuses those files verbatim so DM/FM (ioctl path) and SM (libFCS path)
// exercise the exact same on-disk simulator state.

#ifdef SPDM_SIM

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "CommandHeader.h"
#include "altera_fcs_structs.h"
#include "spdmSimulator.h"
#include "utils.h"

#if __GNUC__ >= 4
    #define FCS_DLLEXPORT __attribute__ ((visibility ("default")))
#else
    #define FCS_DLLEXPORT
#endif

namespace {

// ----------------------------------------------------------------------------
// Hex helpers (kept self-contained so libFCS.so does not depend on the
// ioctl mock translation unit).
// ----------------------------------------------------------------------------

bool nibble(char c, uint8_t& n) {
    if (c >= '0' && c <= '9') { n = static_cast<uint8_t>(c - '0');      return true; }
    if (c >= 'a' && c <= 'f') { n = static_cast<uint8_t>(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { n = static_cast<uint8_t>(c - 'A' + 10); return true; }
    return false;
}

bool decodeHex(const std::string& s, std::vector<uint8_t>& out) {
    std::string t;
    t.reserve(s.size());
    for (char c : s) {
        if (!std::isspace(static_cast<unsigned char>(c))) t.push_back(c);
    }
    if (t.size() >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        t.erase(0, 2);
    }
    if (t.empty() || (t.size() % 2) != 0) return false;
    out.clear();
    out.reserve(t.size() / 2);
    for (size_t i = 0; i < t.size(); i += 2) {
        uint8_t hi = 0, lo = 0;
        if (!nibble(t[i], hi) || !nibble(t[i + 1], lo)) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

std::string slurpFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return {};
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// Return the active simulator dir (./spdmSim1.2 or ./spdmSim1.5) so the
// helper files (chipid.txt, idcode.txt) are looked up next to the certs/
// directory the SPDM lib already uses.
std::string spdmSimDir() {
    std::string dir;
    SpdmSimulator::get_spdmSim_info(nullptr, nullptr, nullptr, &dir, nullptr);
    return dir;
}

// ----------------------------------------------------------------------------
// chipid.txt / idcode.txt loaders (same files the ioctl mock consumes).
// ----------------------------------------------------------------------------

constexpr const char* kDefaultChipIdHex = "1234567890abcdef";
constexpr uint32_t    kDefaultIdCode    = 0x6341D0DDu; // Agilex (family 0x34)

bool readChipIdBE(uint8_t out[8]) {
    const std::string path = spdmSimDir() + "/chipid.txt";
    std::vector<uint8_t> bytes;
    if (decodeHex(slurpFile(path), bytes) && bytes.size() == 8) {
        std::memcpy(out, bytes.data(), 8);
        return true;
    }
    if (decodeHex(kDefaultChipIdHex, bytes) && bytes.size() == 8) {
        std::memcpy(out, bytes.data(), 8);
    }
    return false;
}

uint32_t readIdCode() {
    const std::string path = spdmSimDir() + "/idcode.txt";
    std::vector<uint8_t> bytes;
    if (decodeHex(slurpFile(path), bytes) && bytes.size() == 4) {
        return (static_cast<uint32_t>(bytes[0]) << 24)
             | (static_cast<uint32_t>(bytes[1]) << 16)
             | (static_cast<uint32_t>(bytes[2]) <<  8)
             |  static_cast<uint32_t>(bytes[3]);
    }
    return kDefaultIdCode;
}

// pdi.txt holds 40 hex chars = 20-byte device PDI. BKPS only consumes the
// first 20 bytes of the 32-byte deviceIdentity blob (SkiHelper.getPdiForUrlFrom
// -> Arrays.copyOf(.., 20)) to form the prefetch zip URL, so the remaining
// 12 bytes are zero-padded.
constexpr size_t kPdiLen = 20;
constexpr size_t kDeviceIdentityLen = 32;

bool readPdi(uint8_t out[kPdiLen]) {
    const std::string path = spdmSimDir() + "/pdi.txt";
    std::vector<uint8_t> bytes;
    if (decodeHex(slurpFile(path), bytes) && bytes.size() == kPdiLen) {
        std::memcpy(out, bytes.data(), kPdiLen);
        return true;
    }
    return false;
}

// MCTP command frames bkp_app sends are already wire-formatted (CommandHeader
// prepended on the SPDM side); SpdmSimulator::sendCommand wraps the input in
// the expected mailbox header for fpga_mailbox(). For MCTP we just forward.
constexpr uint16_t MCTP_OPCODE = 0x194; // SDM_COMMAND_CODE::MCTP

// ----------------------------------------------------------------------------
// Cert request mapping. The real libFCS.so for Agilex strips the certificate
// type word coming back from the firmware before returning the DER body.
// Our SpdmSimulator::sendGetAttestationCommand already returns
//     [ 4-byte cert_type word ][ DER cert ][ optional padding ]
// (see serveAgilexCert + the regular SPDM path). bkp_app's
// FcsCommunicationFcsLib::getAttestationCertificate copies whatever
// fcs_attestation_get_certificate writes into outBuffer, so we mirror what
// the real lib produces (which keeps the leading cert_type word for BKPS's
// GetCertificateResponseBuilder.parse()).
// ----------------------------------------------------------------------------

} // namespace

extern "C" {

// chip id is reported as two 32-bit halves; bkp_app then little-endian
// encodes them. The chipid.txt file holds 16 hex chars in big-endian
// "human" order, matching what the ioctl mock has always served.
FCS_DLLEXPORT int fcs_get_chip_id(uint32_t* chip_id_lo, uint32_t* chip_id_hi)
{
    if (chip_id_lo == nullptr || chip_id_hi == nullptr) { return 1; }
    uint8_t be[8] = {0};
    readChipIdBE(be);
    uint32_t lo = 0, hi = 0;
    for (int i = 0; i < 4; ++i) {
        lo |= static_cast<uint32_t>(be[i])     << (8 * i);
        hi |= static_cast<uint32_t>(be[i + 4]) << (8 * i);
    }
    *chip_id_lo = lo;
    *chip_id_hi = hi;
    return 0;
}

// JTAG idcode: BKPS's GetIdCodeResponseBuilder applies an L2B swap on the
// wire bytes, so writing the logical 32-bit value via memcpy on a little-
// endian host yields the right value once parsed.
FCS_DLLEXPORT int fcs_get_jtag_idcode(uint32_t* idcode)
{
    if (idcode == nullptr) { return 1; }
    *idcode = readIdCode();
    return 0;
}

// Attestation certificate: hand off to the SPDM simulator (which has its
// own family-aware override for AgilexB types 0x10/0x20/0x80 and falls
// back to the upstream sim_mailbox path for anything else).
FCS_DLLEXPORT int fcs_attestation_get_certificate(int cert_request,
                                                  char* cert,
                                                  uint32_t* cert_size)
{
    if (cert == nullptr || cert_size == nullptr) { return 1; }
    std::vector<uint8_t> out;
    int status = SpdmSimulator::sendGetAttestationCommand(cert_request, out);
    if (status != 0) { return status; }
    if (out.size() > *cert_size) { return 1; }
    std::memcpy(cert, out.data(), out.size());
    *cert_size = static_cast<uint32_t>(out.size());
    return 0;
}

// Generic MCTP/SPDM command: pass the buffer straight through to the
// simulator. SpdmSimulator::sendCommand prepends the mailbox header, calls
// fpga_mailbox(), then strips the leading word from the response, which
// is exactly what the real libFCS.so does (the SDM mailbox header is an
// implementation detail of the on-chip path).
FCS_DLLEXPORT int fcs_mctp_cmd_send(char* mctp_cmd, int cmd_len,
                                    char* mctp_resp, int* resp_len)
{
    if (mctp_cmd == nullptr || mctp_resp == nullptr || resp_len == nullptr) {
        return 1;
    }
    std::vector<uint8_t> in(reinterpret_cast<uint8_t*>(mctp_cmd),
                            reinterpret_cast<uint8_t*>(mctp_cmd) + cmd_len);
    std::vector<uint8_t> out;
    int status = SpdmSimulator::sendCommand(MCTP_OPCODE, in, out);
    if (status != 0) { return status; }
    if (static_cast<int>(out.size()) > *resp_len) { return 1; }
    std::memcpy(mctp_resp, out.data(), out.size());
    *resp_len = static_cast<int>(out.size());
    return 0;
}

// GET_DEVICE_IDENTITY (mailbox 0x500) - serves the 32-byte deviceIdentity
// blob from ${spdmSimDir}/pdi.txt (mirroring how chipid.txt / idcode.txt
// drive the other identity-reporting commands). BKPS uses the first 20
// bytes as the prefetch zip id (SkiHelper.getPdiForUrlFrom), so the
// caller is expected to write the device PDI as 40 hex chars there.
// We do NOT forward to libfirmware_spdm_sim.so because its GET_DEVICE_IDENTITY
// handler returns a hardcoded constant that doesn't match the AACS-issued
// SM device PDI.
FCS_DLLEXPORT int fcs_get_device_identity(char* dev_identity,
                                          int* dev_identity_length)
{
    if (dev_identity == nullptr || dev_identity_length == nullptr) {
        return 1;
    }
    if (*dev_identity_length < static_cast<int>(kDeviceIdentityLen)) {
        return 1;
    }
    uint8_t pdi[kPdiLen] = {0};
    readPdi(pdi);
    std::memset(dev_identity, 0, kDeviceIdentityLen);
    std::memcpy(dev_identity, pdi, kPdiLen);
    *dev_identity_length = static_cast<int>(kDeviceIdentityLen);
    return 0;
}

// QSPI is a host-local feature on real hardware; the simulator has no QSPI
// flash. bkp_app's BKP provisioning flow does not exercise QSPI for
// AgilexB, but the FcsCommunicationFcsLib loader asserts every symbol is
// present, so we expose them as no-ops that succeed for the dummy values
// fcsMock.cpp already validates against (chipSel=0, qspiAddr=0, len=0x200)
// and otherwise fail loudly. This keeps the surface minimal without
// silently masking real misuse.

FCS_DLLEXPORT int fcs_qspi_open()  { return 0; }
FCS_DLLEXPORT int fcs_qspi_close() { return 0; }

FCS_DLLEXPORT int fcs_qspi_set_cs(uint32_t chipSel)
{
    return (chipSel != 0) ? 1 : 0;
}

FCS_DLLEXPORT int fcs_qspi_erase(uint32_t qspiAddr, uint32_t numWords)
{
    return ((qspiAddr != 0) || (numWords != 0x200)) ? 1 : 0;
}

FCS_DLLEXPORT int fcs_qspi_read(uint32_t qspiAddr, char* buffer, uint32_t numWords)
{
    if (buffer == nullptr) { return 1; }
    if (qspiAddr != 0 || numWords != 0x200) { return 1; }
    std::memset(buffer, 0, numWords * 4);
    return 0;
}

FCS_DLLEXPORT int fcs_qspi_write(uint32_t qspiAddr, char* buffer, uint32_t numWords)
{
    (void)buffer;
    return ((qspiAddr != 0) || (numWords != 0x200)) ? 1 : 0;
}

// libfcs_init: real lib opens the kernel device. The simulator lazily
// init's libfirmware_spdm_sim.so on first SpdmSimulator::sendCommand
// call, so this is a no-op besides the log_level argument the caller
// passes in.
FCS_DLLEXPORT int libfcs_init(char* log_level)
{
    (void)log_level;
    return 0;
}

} // extern "C"

#endif // SPDM_SIM
