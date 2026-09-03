#  This project is licensed as below.
#
#  ***************************************************************************
#
#  Copyright 2020-2025 Altera Corporation. All Rights Reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  1. Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright
#  notice, this list of conditions and the following disclaimer in the
#  documentation and/or other materials provided with the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
#  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  ***************************************************************************

import json
import sys

from Modules.Encryptor import Encryptor
from Modules.Utilities import is_hex, contains_hex_encoded_length_one_of, check_list_numbers, parse_list_numbers, \
    split_array, check_number, is_json, verify_hex_input


supported_puf_types = ["IID", "IIDUSER", "EFUSE"]


class ConfigurationDTO:
    import_mode = None
    name = None
    puf_type = None
    require_iid_uds = None  # boolean
    test_mode_secrets = None  # boolean
    corim_url = None
    e_fuses_public_value = None  # hex encoded value
    aes_key_value = None  # hex encoded value
    qek_value = None  # hex encoded value
    e_fuses_public_mask = None  # hex encoded value
    overbuild_max = None
    sdm_svns = None
    sdm_build_id_strings = None
    rom_versions = None
    test_program = None  # boolean
    key_name = None

    def __init__(self):
        pass

    def from_json(self, raw_json):
        if not is_json(raw_json):
            print('Payload for configuration is not in JSON format')
            sys.exit()

        parsed = json.loads(raw_json)

        self.import_mode = parsed['confidentialData']['importMode']
        self.name = parsed['name']
        if 'testProgram' in parsed['confidentialData']['aesKey']:
            self.test_program = parsed['confidentialData']['aesKey']['testProgram']
        self.puf_type = parsed['pufType']
        if 'requireIidUds' in parsed:
            self.require_iid_uds = parsed['requireIidUds']
        if 'testModeSecrets' in parsed:
            self.test_mode_secrets = parsed['testModeSecrets']
        if 'corimUrl' in parsed:
            self.corim_url = parsed['corimUrl']
        if 'qek' in parsed['confidentialData']:
            self.qek_value = parsed['confidentialData']['qek']['value']
            self.key_name = parsed['confidentialData']['qek']['keyName']
        self.aes_key_value = parsed['confidentialData']['aesKey']['value']
        self.e_fuses_public_value = parsed['attestationConfig']['efusesPublic']['value']
        self.e_fuses_public_mask = parsed['attestationConfig']['efusesPublic']['mask']
        self.overbuild_max = parsed['overbuild']['max']
        self.sdm_svns = ",".join(map(str, parsed['attestationConfig']['blackList']['sdmSvns']))
        self.sdm_build_id_strings = ",".join(parsed['attestationConfig']['blackList']['sdmBuildIdStrings'])
        self.rom_versions = ",".join(map(str, parsed['attestationConfig']['blackList']['romVersions']))

    def from_user(self):
        self.import_mode = self.input_import_mode()
        self.name = self.input_configuration_name()
        self.puf_type = self.input_puf_type()
        self.require_iid_uds = self.input_require_iid_uds()
        self.test_mode_secrets = self.input_test_mode_secrets()
        self.corim_url = self.input_corim_url()
        self.overbuild_max = self.input_overbuild_counter()
        self.test_program = self.input_test_program()

        self.aes_key_value = self.input_aes_key_value()
        self.qek_value = self.input_qek_value()
        if (self.qek_value):
            self.key_name = self.input_key_name()
        self.e_fuses_public_value = self.input_efuses_pub_value()
        self.e_fuses_public_mask = self.input_efuses_pub_mask()

        self.sdm_svns = self.input_sdm_svns()
        self.sdm_build_id_strings = self.input_sdm_build_id_strings()
        self.rom_versions = self.input_rom_versions()

    @staticmethod
    def input_import_mode():
        while True:
            usr_input = input('Choose import mode [PLAINTEXT/ENCRYPTED]: ')
            to_verify = usr_input.upper()
            if to_verify in ("PLAINTEXT", "ENCRYPTED"):
                return to_verify

    @staticmethod
    def input_configuration_name():
        while True:
            usr_input = input('Enter configuration name: ')
            if usr_input and len(usr_input) > 0:
                return usr_input

    @staticmethod
    def input_puf_type():
        while True:
            usr_input = input(f'Choose PUF Type {supported_puf_types}: ')
            to_verify = usr_input.upper()
            if to_verify in supported_puf_types:
                return to_verify

    @staticmethod
    def input_require_iid_uds():
        while True:
            usr_input = input('Choose if IID UDS certificate chain should be verified '
                              'in addition to regular chain [Y/N]: ')
            to_verify = usr_input.upper()
            if to_verify in ("Y", "N"):
                return to_verify == "Y"

    @staticmethod
    def input_test_mode_secrets():
        while True:
            usr_input = input('Will this configuration be used for non secure (non real-OWNED) devices [Y/N]: ')
            to_verify = usr_input.upper()
            if to_verify in ("Y", "N"):
                return to_verify == "Y"

    @staticmethod
    def input_corim_url():
        while True:
            usr_input = input('Enter CoRIM url: ')
            if not usr_input or len(usr_input) <= 255:
                return usr_input
            else:
                print('Parameter should be left empty or have length between 1 and 255 chars')

    @staticmethod
    def input_overbuild_counter():
        default = -1
        while True:
            usr_input = input('Enter overbuild max counter. Default: -1 for unlimited: ')
            if usr_input and len(usr_input) > 0 and check_number(usr_input):
                return int(usr_input)
            elif not usr_input or len(usr_input) == 0:
                return default

    @staticmethod
    def input_aes_key_value():
        while True:
            value = input('Enter AES Key or User AES Root Key Certificate hex encoded: ')
            usr_input = verify_hex_input(value)
            if usr_input and len(usr_input) > 0:
                return usr_input

    @staticmethod
    def input_qek_value():
        value = input('Enter Quartus Encryption Key (QEK) hex encoded: ')
        usr_input = verify_hex_input(value)
        return usr_input

    @staticmethod
    def input_key_name():
        while True:
            usr_input = input('Enter key name for QEK encryption key to be loaded from BKPS HSM: ')
            if usr_input and len(usr_input) > 0:
                return usr_input
            else:
                print('Parameter cannot be empty.')

    @staticmethod
    def input_efuses_pub_value():
        while True:
            value = input('Enter E-FUSES public value hex encoded: ')
            usr_input = verify_hex_input(value)
            if contains_hex_encoded_length_one_of(usr_input, [256, 1024]):
                return usr_input
            else:
                print('Parameter should have 256 or 1024 bytes')

    @staticmethod
    def input_efuses_pub_mask():
        while True:
            value = input('Enter E-FUSES public mask hex encoded: ')
            usr_input = verify_hex_input(value)
            if contains_hex_encoded_length_one_of(usr_input, [256, 1024]):
                return usr_input
            else:
                print('Parameter should have 256 or 1024 bytes')

    @staticmethod
    def input_sdm_svns():
        while True:
            usr_input = input('List of SDM SVNs (should contain only numbers comma separated): ')
            if usr_input and len(usr_input) > 0:
                usr_input_split = usr_input.split(',')
                if check_list_numbers(usr_input_split):
                    return usr_input
                else:
                    print('List of SDM SVNs should contain only non-negative numbers')
            else:
                break

    @staticmethod
    def input_sdm_build_id_strings():
        while True:
            usr_input = input('List of build ID strings (should contain strings comma separated): ')
            if usr_input and len(usr_input) > 0:
                return usr_input
            else:
                break

    @staticmethod
    def input_rom_versions():
        while True:
            usr_input = input('List of ROM versions (should contain only numbers comma separated): ')
            if usr_input and len(usr_input) > 0:
                usr_input_split = usr_input.split(',')
                if check_list_numbers(usr_input_split):
                    return usr_input
                else:
                    print('List of ROM versions should contain only non-negative numbers')
            else:
                break

    @staticmethod
    def input_test_program():
        while True:
            is_test_program = input('Will this Configuration be used for testing (Y/N): ')
            if is_test_program.upper() in ("Y", "N"):
                return is_test_program.upper() == "Y"


class Configurator:
    requester = None
    dto = None

    aes_key_dto = {}
    qek_dto = {}
    overbuild_dto = {}
    confidentialData = {}
    rom_versions = []
    sdm_build_id_strings = []
    sdm_svns = []
    black_list_dto = {}
    e_fuses_public_dto = {}
    attestation_config = {}
    init_configuration = {}

    def __init__(self, is_debug, requester, dto):
        self.requester = requester
        self.debug_enabled = is_debug
        self.dto = dto
        self.verify()
        pass

    def prepare(self):
        self.init_configuration['pufType'] = self.dto.puf_type
        self.init_configuration['name'] = self.dto.name

        self.overbuild_dto['max'] = int(self.dto.overbuild_max)
        self.init_configuration['overbuild'] = self.overbuild_dto

        self.init_configuration['requireIidUds'] = self.dto.require_iid_uds
        self.init_configuration['testModeSecrets'] = self.dto.test_mode_secrets
        self.init_configuration['corimUrl'] = self.dto.corim_url

        if self.dto.import_mode == 'ENCRYPTED':
            # Get Import Key in PEM
            bkps_import_pub_key_pem = self.requester.get_service_import_public_key(None, True)

            if bkps_import_pub_key_pem is None:
                print('Unable to fetch Service Import Public Key from BKPS')
                sys.exit()

            encryptor = Encryptor(bkps_import_pub_key_pem)
            self.aes_key_dto['value'] = encryptor.encrypt(self.dto.aes_key_value)
            self.confidentialData['encryptedAesKey'] = encryptor.get_encrypted_key()
            if (self.dto.qek_value and len(self.dto.qek_value) > 0):
                self.qek_dto['value'] = encryptor.encrypt(self.dto.qek_value)
                self.confidentialData['encryptedQek'] = encryptor.get_encrypted_key()
        else:
            self.aes_key_dto['value'] = self.dto.aes_key_value
            if (self.dto.qek_value and len(self.dto.qek_value) > 0):
                self.qek_dto['value'] = self.dto.qek_value

        self.confidentialData['aesKey'] = self.aes_key_dto
        if (len(self.qek_dto) > 0 and self.qek_dto.get('value')):
            self.qek_dto['keyName'] = self.dto.key_name
            self.confidentialData['qek'] = self.qek_dto
        self.confidentialData['importMode'] = self.dto.import_mode
        self.aes_key_dto['testProgram'] = self.dto.test_program

        self.init_configuration['confidentialData'] = self.confidentialData

        self.black_list_dto['romVersions'] = self.rom_versions
        self.black_list_dto['sdmBuildIdStrings'] = self.sdm_build_id_strings
        self.black_list_dto['sdmSvns'] = self.sdm_svns
        self.attestation_config['blackList'] = self.black_list_dto

        self.e_fuses_public_dto['mask'] = self.dto.e_fuses_public_mask
        self.e_fuses_public_dto['value'] = self.dto.e_fuses_public_value
        self.attestation_config['efusesPublic'] = self.e_fuses_public_dto

        self.init_configuration['attestationConfig'] = self.attestation_config

        if self.debug_enabled:
            print(json.dumps(self.init_configuration, sort_keys=False, indent=4))

        return json.dumps(self.init_configuration)

    def verify(self):
        if not self.dto.import_mode:
            print('importMode parameter is required')
            sys.exit()
        else:
            mode = self.dto.import_mode.upper()
            if mode not in ("PLAINTEXT", "ENCRYPTED"):
                print('Invalid import mode. Please use one of: PLAINTEXT/ENCRYPTED')
                sys.exit()

        if not self.dto.name:
            print('name parameter is required')
            sys.exit()

        if not self.dto.puf_type:
            print('pufType parameter is required')
            sys.exit()
        else:
            puf_type_parsed = self.dto.puf_type.upper()
            if puf_type_parsed not in supported_puf_types:
                print(f'Invalid Puf Type. Please use one of: {supported_puf_types}')
                sys.exit()
            self.dto.puf_type = puf_type_parsed

        if not self.dto.aes_key_value:
            print('aes_key_value parameter is required')
            sys.exit()
        elif not is_hex(self.dto.aes_key_value):
            print('aes_key_value parameter should be hex encoded')
            sys.exit()
        if not self.dto.e_fuses_public_value:
            print('e_fuses_public_value parameter is required')
            sys.exit()
        elif not is_hex(self.dto.e_fuses_public_value):
            print('e_fuses_public_value parameter should be hex encoded')
            sys.exit()
        elif not contains_hex_encoded_length_one_of(self.dto.e_fuses_public_value, [256, 1024]):
            print('e_fuses_public_value parameter should have 256 or 1024 bytes: ')
            sys.exit()

        if not self.dto.e_fuses_public_mask:
            print('e_fuses_public_mask parameter is required')
            sys.exit()
        elif not is_hex(self.dto.e_fuses_public_mask):
            print('e_fuses_public_mask parameter should be hex encoded')
            sys.exit()
        elif not contains_hex_encoded_length_one_of(self.dto.e_fuses_public_mask, [256, 1024]):
            print('e_fuses_public_mask parameter should have 256 or 1024 bytes')
            sys.exit()

        rom_version_parsed = split_array(self.dto.rom_versions)
        if check_list_numbers(rom_version_parsed):
            self.rom_versions = parse_list_numbers(rom_version_parsed)
        else:
            print('List of ROM versions should contain only numbers')
            sys.exit()

        self.sdm_build_id_strings = split_array(self.dto.sdm_build_id_strings)

        sdm_svns_parsed = split_array(self.dto.sdm_svns)
        if check_list_numbers(sdm_svns_parsed):
            self.sdm_svns = parse_list_numbers(sdm_svns_parsed)
        else:
            print('List of SDM SVNs should contain only numbers')
            sys.exit()
