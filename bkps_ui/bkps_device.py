#!/usr/bin/env python3
"""JTAG-based device provisioning for Intel FPGAs (connection, fuses, RKH, BKP, JIC, CoRIM, SPDM)."""

import os
from bkps_config import Config
from bkps_printer import print_header, print_step, print_success, print_warning, print_error, print_info
from bkps_runner import _ps_run, get_output

# Hoisted (previously inline) imports
import shutil
import re



# ── JTAG Connection & Status ─────────────────────────────────────────────────

def check_jtag_connection(cfg: Config) -> bool:
    """Detect JTAG cables and verify the target device is visible."""
    print_header("Checking JTAG Connection")

    print_step(1, "Detecting JTAG cables and devices...")
    # jtagconfig lists all connected cables and devices on the JTAG chain;
    # empty output means no USB-Blaster or similar cable is connected.
    output = get_output(["jtagconfig"])
    if not output.strip():
        print_warning("No JTAG cables detected")
        return False

    print_info(f"JTAG chain:\n{output}")

    print_step(2, f"Looking for device {cfg.device_part}...")
    if cfg.device_part in output:
        print_success(f"Device detected: {cfg.device_part}")
        return True
    else:
        print_error(f"Device {cfg.device_part!r} not found in JTAG chain")
        return False


# ── Root-Key-Hash Provisioning ───────────────────────────────────────────────

def check_jtag_status(cfg: Config, status_type: str) -> None:
    """Query JTAG provisioning/config status from the device.

    Args:
        status_type: "PROV" (provisioning fuse state) or "CONFIG" (configuration status).
    """
    print_header(f"Checking JTAG {status_type} Status")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag --status --status_type={status_type}")


def read_fuse_info(cfg: Config) -> None:
    """Read current fuse information from the connected device over JTAG into fuse_report.fuse."""
    print_header("Reading Fuse Info via JTAG")

    cm_dir = cfg.cm_provisioning_dir
    os.makedirs(cm_dir, exist_ok=True)
    fuse_report_name = "fuse_report.fuse"
    fuse_report_path = os.path.join(cm_dir, fuse_report_name)

    print_step(1, "Reading fuse report from device...")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag -o\"ei;{fuse_report_name};{cfg.device_part}\"",
        cwd=cm_dir)

    print_success(f"Fuse report saved: {fuse_report_path}")


def _owner_rkh_already_provisioned(cfg: Config) -> bool:
    """Return True if device PROV status already lists the owner RKH."""
    cmd = (
        f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag "
        f"--status --status_type=PROV"
    )
    try:
        result = _ps_run(cmd, capture=True, check=False)
    except Exception as exc:
        print_warning(f"PROV status query failed ({exc}); will attempt RKH programming.")
        return False
    text = ""
    if result is not None:
        text = f"{result.stdout or ''}{result.stderr or ''}"
    return "Owner root public key hash" in text


def provision_rkh_virtual(cfg: Config) -> None:
    """Program root0.qky root key hash to device eFuses, skipping if already present (except stratix10)."""
    print_header("Provisioning RKH")

    print_step(1, "Checking PROV status for existing Owner root public key hash...")
    if cfg.profile_name != "stratix10" and _owner_rkh_already_provisioned(cfg):
        print_info(
            "Owner root public key hash already present in PROV status — "
            "skipping root key hash programming."
        )
        print_success("RKH already provisioned (skipped)")
        return

    print_info("Owner root public key hash not found in PROV status — programming RKH.")

    cm_dir = cfg.cm_provisioning_dir
    os.makedirs(cm_dir, exist_ok=True)
    root_qky_src = os.path.join(cfg.quartus_keys_dir, "root0.qky")
    root_qky_dst = os.path.join(cm_dir, "root0.qky")

    if not os.path.isfile(root_qky_src):
        print_error(f"root0.qky not found: {root_qky_src}")
        raise FileNotFoundError(root_qky_src)

    print_step(2, "Copying root0.qky to CM provisioning folder...")
    shutil.copy2(root_qky_src, root_qky_dst)
    print_success("root0.qky copied")

    print_step(3, "Programming root key hash to eFuses...")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag -o\"pv;root0.qky\"",
        cwd=cm_dir)
    print_success("RKH programmed")


# ── Black Key Provisioning ───────────────────────────────────────────────────

def run_bkp(cfg: Config) -> None:
    """Execute Black Key Provisioning on the connected device using bkp_options.txt."""
    print_header("Running Black Key Provisioning")
    print_step(1, "Executing BKP...")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag --device 1 --bkp_options=bkp_options.txt", cwd=cfg.cm_provisioning_dir)

    print_step(2, "Verifying AES key provisioning...")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag --status --status_type=PROV")


# ── Device Onboarding ──────────────────────────────────────────────────────

def program_helper_image(cfg: Config) -> None:
    """Program a PROVISION helper image to the device via JTAG."""
    print_header("Programming PROVISION Helper Image")
    _ps_run(f"quartus_pfg --helper_image -o subtype=PROVISION -o helper_device={cfg.device_part} provision.rbf")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag -o\"p;provision.rbf\" --force")
    print_success("Programmed PROVISION Helper Image successfully")

def program_jic(cfg: Config, jic_path: str) -> None:
    """Program a JIC file to the device via JTAG.

    Args:
        jic_path: Absolute path to the .jic file to program.
    """
    print_header("Programming JIC File")
    print_step(1, f"Programming {jic_path} ...")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag -o\"pv;{jic_path}\"")
    print_success("JIC programmed successfully")


def bkp_prefetch(cfg: Config) -> None:
    """Cache AACS certificates and CRLs in BKPS for this device."""
    print_header("BKP Prefetch")
    print_step(1, "Fetching and caching device certificates from Intel IPCS...")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag --bkp_options=bkp_options.txt --bkp_prefetch", cwd=cfg.cm_provisioning_dir)
    print_success("Prefetch completed")


def bkp_puf_activate(cfg: Config, puf_type: str) -> None:
    """Provision and activate the PUF helper data to the device.

    Args:
        puf_type: PUF type string, e.g. "UDS_EFUSE" (default) or "UDS_IID".
    """
    print_header("PUF activate")
    print_step(1, f"Issuing PUF activate (puf_type={puf_type})...")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag --bkp_options=bkp_options.txt --puf_type={puf_type} --bkp_puf_activate", cwd=cfg.cm_provisioning_dir)
    print_success("PUF activate completed")


def bkp_set_authority(cfg: Config, puf_type: str, slot_id: int = 0) -> None:
    """Provision the Intel authority certificate chain to the device (SPDM Set Authority).

    Args:
        puf_type: PUF type string, e.g. "UDS_EFUSE" (default) or "UDS_IID".
        slot_id: SPDM slot ID to use (0-7); 0 is the primary slot.
    """
    print_header("Set Authority")
    print_step(1, f"Issuing SPDM Set Authority (puf_type={puf_type}, slot_id={slot_id})...")
    _ps_run(f"quartus_pgm -c {cfg.jtag_cable_num} -mjtag --bkp_options=bkp_options.txt --puf_type={puf_type} --slot_id={slot_id} --bkp_set_authority", cwd=cfg.cm_provisioning_dir)
    print_success("Set Authority completed")


# ── CoRIM URL Extraction ───────────────────────────────────────────────────

def generate_provision_helper_rbf(cfg: Config, work_dir: str = None) -> str:
    """Generate a PROVISION helper image RBF for cfg.device_part in cfg.cm_provisioning_dir."""
    work_dir = cfg.cm_provisioning_dir
    if not work_dir:
        raise RuntimeError(
            "cm_provisioning_dir is empty — set 'CM Provisioning Dir' on the "
            "Config tab before running the AES pipeline."
        )
    device = (cfg.device_part or "").strip()
    if not device:
        raise RuntimeError(
            "device_part is empty — set Device Part on the Config tab "
            "before generating the PROVISION helper image."
        )
    os.makedirs(work_dir, exist_ok=True)
    print_header("Generating PROVISION Helper Image")
    print_step(1, f"quartus_pfg --helper_image (device={device})...")
    _ps_run(
        f"quartus_pfg --helper_image -o subtype=PROVISION "
        f"-o helper_device={device} provision.rbf",
        cwd=work_dir,
    )
    rbf_path = os.path.join(work_dir, "provision.rbf")
    if not os.path.isfile(rbf_path):
        raise RuntimeError(
            f"quartus_pfg did not produce provision.rbf in {work_dir}"
        )
    print_success(f"Helper image written: {rbf_path}")
    return rbf_path


def extract_corim_url(cfg: Config, rbf_path: str) -> str:
    """Extract the CoRIM URL from an RBF via quartus_pfg corim/diag conversion.

    Args:
        rbf_path: Path to the RBF file to extract from.
    """
    print_header("Extracting CoRIM URL")

    if not rbf_path or not os.path.isfile(rbf_path):
        raise FileNotFoundError(f"RBF not found: {rbf_path}")

    work_dir = os.path.dirname(os.path.abspath(rbf_path))
    rbf_name = os.path.basename(rbf_path)
    stem = os.path.splitext(rbf_name)[0]
    corim_name = f"{stem}.corim"
    diag_name  = f"{stem}.diag"

    print_step(1, f"Generating {corim_name} from {rbf_name}...")
    _ps_run(f"quartus_pfg -c {rbf_name} {corim_name}", cwd=work_dir)
    print_success(f"{corim_name} generated")

    print_step(2, f"Decoding {corim_name} → {diag_name}...")
    _ps_run(f"quartus_pfg -c {corim_name} {diag_name}", cwd=work_dir)
    print_success(f"{diag_name} generated")

    print_step(3, "Parsing CoRIM URL from diagnostic file...")
    diag_path = os.path.join(work_dir, diag_name)
    with open(diag_path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    # Find all non-empty href values inside corim.dependent-rims /
    # corim-locator maps.  CDDL diagnostic notation uses '/ corim.href /'
    # as the field key; empty locators appear as 32( "").
    urls = re.findall(r'/ corim\.href / 0 : 32\(\s*"(https?://[^"]+)"', content)
    if not urls:
        raise RuntimeError(
            f"No corim.href URL found in {diag_name}. "
        )

    url = urls[0]
    print_success(f"CoRIM URL: {url}")
    return url


def extract_and_save_corim_url_from_provision_helper(cfg: Config) -> str:
    """Generate a PROVISION helper RBF, extract its CoRIM URL, and save it to quartus_keys_dir/corim_url.txt."""
    rbf_path = generate_provision_helper_rbf(cfg)
    url = extract_corim_url(cfg, rbf_path)

    keys_dir = cfg.quartus_keys_dir
    os.makedirs(keys_dir, exist_ok=True)
    url_file = os.path.join(keys_dir, "corim_url.txt")
    with open(url_file, "w", encoding="utf-8") as fh:
        fh.write(url.strip() + "\n")
    print_success(f"CoRIM URL saved: {url_file}")
    return url


def read_saved_corim_url(cfg: Config) -> str:
    """Return the CoRIM URL previously saved by the AES/provision helper flow."""
    path = os.path.join(cfg.quartus_keys_dir, "corim_url.txt")
    try:
        if not os.path.isfile(path):
            return ""
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


# ── JIC Generation ─────────────────────────────────────────────────────────

# ── PFG XML Builders (internal) ──────────────────────────────────────────────
# Each builder returns a complete PFG XML string for the corresponding device
# family.  Values like partition start/end addresses are fixed by the Intel
# reference flash map and must not be changed without consulting the Quartus
# flash layout documentation.

def _build_pfg_agilex5(output_dir: str, flash_device: str, flash_loader: str, design_rbf: str) -> str:
    """Return PFG XML for Agilex 5.

    Args:
        output_dir: Directory where quartus_pfg will write the JIC.
        flash_device: Flash device type string, e.g. "QSPI512".
        flash_loader: Flash loader device identifier string.
        design_rbf: Filename of the design RBF (relative to output_dir).
    """
    return f"""\
<pfg version="1">
    <settings custom_db_dir="./" mode="ASX4"/>
    <output_files>
        <output_file name="output_files" directory="{output_dir}" type="JIC">
            <file_options/>
            <secondary_file type="MAP" name="output_files_jic">
                <file_options/>
            </secondary_file>
            <secondary_file type="SEC_RPD" name="output_files_jic">
                <file_options bitswap="1"/>
            </secondary_file>
            <secondary_file type="HELPER_RBF" name="output_files_jic">
                <file_options/>
            </secondary_file>
            <flash_device_id>Flash_Device_1</flash_device_id>
        </output_file>
    </output_files>
    <flash_devices>
        <flash_loader>{flash_loader}</flash_loader>
        <flash_device type="{flash_device}" id="Flash_Device_1">
            <partition reserved="1" fixed_s_addr="1" s_addr="0x00000000" factory_fallback="0" e_addr="0x001FFFFF" fixed_e_addr="1" id="BOOT_INFO" size="0"/>
            <partition reserved="1" fixed_s_addr="1" s_addr="0x00200000" e_addr="auto" fixed_e_addr="1" id="BOS" size="65536"/>
            <partition reserved="0" fixed_s_addr="0" s_addr="auto" e_addr="auto" fixed_e_addr="0" id="LITTLEFS" size="0"/>
            <partition reserved="0" fixed_s_addr="0" s_addr="auto" e_addr="auto" fixed_e_addr="0" id="P1" size="0"/>
        </flash_device>
    </flash_devices>
    <bitstreams>
        <bitstream id="Bitstream_1">
            <path>{design_rbf}</path>
        </bitstream>
    </bitstreams>
    <assignments>
        <assignment page="0" partition_id="P1">
            <bitstream_id>Bitstream_1</bitstream_id>
        </assignment>
    </assignments>
</pfg>
"""


def _build_pfg(cfg: Config, output_dir: str, flash_device: str, flash_loader: str,
               design_rbf: str, puf_file: str) -> str:
    """Return PFG XML for Agilex 7, eASIC N5X, or Stratix 10.

    Args:
        output_dir: Directory where quartus_pfg will write the JIC.
        flash_device: Flash device type string, e.g. "MT25QU02G".
        flash_loader: Flash loader device identifier string.
        design_rbf: Filename of the design RBF (relative to output_dir).
        puf_file: .puf helper-data file assigned to the PUF partition on agilex and stratix10.
    """
    raw_section = ""
    puf_assign = ""
    partition_section = ""
    if cfg.profile_name == "agilex":
        raw_section = (
            f'<raw_files>\n<raw_file type="PUF" id="Raw_File_1">{puf_file}</raw_file>\n</raw_files>'
        )
        puf_assign = (
            f'<assignment page="0" partition_id="PUF">\n<raw_file_id>Raw_File_1</raw_file_id>\n</assignment>'
        )
        partition_section = (
            '<partition reserved="1" fixed_s_addr="1" s_addr="auto" e_addr="auto" fixed_e_addr="1" id="PUF" size="65536"/>\n'
            '<partition reserved="0" fixed_s_addr="0" s_addr="auto" e_addr="auto" fixed_e_addr="0" id="LITTLEFS" size="0"/>\n'
        )
    elif cfg.profile_name == "easic_n5x":
        partition_section = (
            '<partition reserved="0" fixed_s_addr="0" s_addr="auto" e_addr="auto" fixed_e_addr="0" id="LITTLEFS" size="0"/>\n'
        )
    elif cfg.profile_name == "stratix10":
        raw_section = (
            f'<raw_files>\n<raw_file type="PUF" id="Raw_File_1">{puf_file}</raw_file>\n</raw_files>'
        )
        puf_assign = (
            f'<assignment page="0" partition_id="PUF">\n<raw_file_id>Raw_File_1</raw_file_id>\n</assignment>'
        )
        partition_section = (
            '<partition reserved="1" fixed_s_addr="1" s_addr="auto" e_addr="auto" fixed_e_addr="1" id="PUF" size="65536"/>\n'
        )

    return f"""\
<pfg version="1">
    <settings custom_db_dir="./" mode="ASX4"/>
    <output_files>
        <output_file name="output_file" directory="{output_dir}" type="JIC">
            <file_options/>
            <flash_device_id>Flash_Device_1</flash_device_id>
        </output_file>
    </output_files>
    <bitstreams>
        <bitstream id="Bitstream_1">
            <path>{design_rbf}</path>
        </bitstream>
    </bitstreams>
    {raw_section}
    <flash_devices>
        <flash_device type="{flash_device}" id="Flash_Device_1">
            <partition reserved="1" fixed_s_addr="1" s_addr="0x00000000" e_addr="0x001FFFFF" fixed_e_addr="1" id="BOOT_INFO" size="0"/>
            {partition_section}
            <partition reserved="0" fixed_s_addr="0" s_addr="auto" e_addr="auto" fixed_e_addr="0" id="P1" size="0"/>
        </flash_device>
        <flash_loader>{flash_loader}</flash_loader>
    </flash_devices>
    <assignments>
        {puf_assign}
        <assignment page="0" partition_id="P1">
            <bitstream_id>Bitstream_1</bitstream_id>
        </assignment>
    </assignments>
</pfg>
"""


def generate_jic(cfg: Config, sof: str | None, output_dir: str,
                 flash_device: str, flash_loader: str, rbf: str | None = None) -> str:
    """Generate a JIC from a plain SOF conversion or an existing RBF.

    BKPS Automation Studio does not alter bitstream protection.  A SOF is
    converted to a plain ``design.rbf``; an operator-provided RBF is copied to
    that name unchanged.  The selected device-family PFG template then packages
    ``design.rbf`` into the JIC.  Signing and encryption, when required, belong
    to the external Quartus design/release flow.

    Args:
        sof: Path to a compiled Quartus SOF; optional when rbf is provided.
        output_dir: Directory where design.rbf, PFG, and JIC are written.
        flash_device: Flash device type, e.g. "MT25QU02G".
        flash_loader: Flash loader device identifier, e.g. "A5ED013BM16ACS".
        rbf: Optional existing RBF; when set, SOF conversion is skipped.
    """
    print_header("Generating JIC File")

    if not sof and not rbf:
        raise ValueError(
            "Must provide either a SOF file or an RBF file to generate a JIC."
        )
    if rbf and not os.path.isfile(rbf):
        raise FileNotFoundError(f"RBF file not found: {rbf}")
    if sof and not os.path.isfile(sof):
        raise FileNotFoundError(f"SOF file not found: {sof}")

    os.makedirs(output_dir, exist_ok=True)
    # Verify the output directory is actually writable before launching Quartus;
    # quartus_pfg gives a cryptic error if it cannot create files there.
    write_test = os.path.join(output_dir, ".bkps_write_test")
    try:
        with open(write_test, "w") as _fh:
            _fh.write("")
        os.remove(write_test)
    except OSError as e:
        raise RuntimeError(
            f"Output directory is not writable: {output_dir}\n{e}"
        ) from e

    design_rbf = "design.rbf"
    if rbf:
        import shutil

        def _stage(src: str, dst_name: str) -> None:
            dst = os.path.join(output_dir, dst_name)
            try:
                same = os.path.exists(dst) and os.path.samefile(src, dst)
            except OSError:
                same = False
            if not same:
                shutil.copyfile(src, dst)

        _stage(rbf, design_rbf)
        next_step = 1
    else:
        print_step(1, f"Generating {design_rbf}...")
        cmd = f"quartus_pfg -c \"{sof}\" \"{design_rbf}\""
        _ps_run(cmd, cwd=output_dir)
        print_success(f"{design_rbf} generated")
        next_step = 2

    # Agilex 7 / Stratix 10 PFG templates always reference a PUF raw file.
    staged_puf = "dummy.puf"
    if cfg.profile_name in ("agilex", "stratix10"):
        dummy_path = os.path.join(output_dir, staged_puf)
        with open(dummy_path, "wb"):
            pass
        print_info(f"Dummy empty PUF file created: {dummy_path}")

    print_step(next_step, "Writing PFG configuration file...")
    # Select flash layout template based on device family
    if cfg.profile_name == "agilex5":
        pfg_xml = _build_pfg_agilex5(output_dir, flash_device, flash_loader, design_rbf)
    else:
        pfg_xml = _build_pfg(cfg, output_dir, flash_device, flash_loader, design_rbf, staged_puf)

    output_stem = "output_files" if cfg.profile_name == "agilex5" else "output_file"
    pfg_path = os.path.join(output_dir, f"{output_stem}.pfg")
    with open(pfg_path, "w") as fh:
        fh.write(pfg_xml)
    print_success(f"PFG written: {pfg_path}")

    print_step(next_step + 1, "Generating JIC file...")
    _ps_run(f"quartus_pfg -c \"{pfg_path}\"", cwd=output_dir)

    jic_path = os.path.join(output_dir, f"{output_stem}.jic")
    if not os.path.isfile(jic_path):
        raise RuntimeError(
            f"quartus_pfg completed without producing the expected JIC: {jic_path}"
        )
    print_success(f"JIC generated: {jic_path}")
    return jic_path
