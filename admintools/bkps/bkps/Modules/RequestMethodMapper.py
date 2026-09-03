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

from Modules.Utilities import is_hex_x_bytes_long, read_file, check_file_soft

class RequestMethodMapper:
    requester = None
    debug = False

    def __init__(self, requester, debug):
        self.requester = requester
        self.debug = debug

    def request_methods(self, params):
        if params.get('health'):
            self.requester.health(params.get('--detailed'))
        elif params.get('service-import-key'):
            if params.get('create'):
                self.requester.create_import_key()
            elif params.get('delete'):
                self.requester.delete_import_key()
        elif params.get('sealing-key'):
            if params.get('create'):
                self.requester.create_sealing_key()
            elif params.get('rotate'):
                self.requester.rotate_sealing_key()
            elif params.get('list'):
                self.requester.list_sealing_keys()
            elif params.get('backup'):
                import_pub_key = self.requester.prepare_payload_from_file(params.get('--input'))
                self.requester.backup_sealing_key(import_pub_key, params.get('--output'))
            elif params.get('restore'):
                encrypted_sealing_key = self.requester.prepare_payload_from_file(params.get('--input'))
                self.requester.restore_sealing_key(encrypted_sealing_key)
        elif params.get('context-key') and params.get('rotate'):
            self.requester.rotate_context_key()
        elif params.get('signing-key'):
            if params.get('create'):
                self.requester.create_signing_key()
            elif params.get('get'):
                self.requester.get_signing_key(params.get('ID'), params.get('--output'))
            elif params.get('list'):
                self.requester.list_signing_keys()
            elif params.get('upload'):
                self.requester.upload_signing_key(params.get('ID'), params.get('SINGLE_FILE'), params.get('MULTI_FILE'))
            elif params.get('activate'):
                self.requester.activate_signing_key(params.get('ID'))
        elif params.get('root-signing-key') and params.get('add'):
            self.requester.add_root_signing_pub_key(params.get('--input'))
        elif params.get('service-import-pub-key') and params.get('get'):
            self.requester.get_service_import_public_key(params.get('--output'))
        elif params.get('configuration'):
            if params.get('list'):
                self.requester.list_configuration()
            elif params.get('get') and params.get('ID'):
                self.requester.get_configuration(params.get('ID'))
            elif params.get('create') or params.get('update'):
                from Modules.Configurator import Configurator, ConfigurationDTO

                payload = None
                if params.get('--json'):
                    raw_json = self.requester.prepare_payload_from_file(params.get('--input'))
                    dto = ConfigurationDTO()
                    dto.from_json(raw_json)
                    configurator = Configurator(self.debug, self.requester, dto)
                    payload = configurator.prepare()
                elif params.get('--interactive'):
                    dto = ConfigurationDTO()
                    dto.from_user()
                    configurator = Configurator(self.debug, self.requester, dto)
                    payload = configurator.prepare()

                if params.get('create'):
                    self.requester.create_configuration(payload)
                elif params.get('update'):
                    self.requester.update_configuration(payload, params.get('ID'))
            elif params.get('delete') and params.get('ID'):
                self.requester.delete_configuration(params.get('ID'))
        elif params.get('user'):
            if params.get('create'):
                self.show_system_reboot_info()
                self.requester.app_user_create(params.get('--input'), params.get('--output'))
            elif params.get('initial-create'):
                self.show_system_reboot_info()
                self.requester.app_user_create_initial(params.get('TOKEN'), params.get('--input'),
                                                       params.get('--output'))
            elif params.get('list'):
                self.requester.app_user_list()
            elif params.get('role-set'):
                self.requester.app_user_set_role(params.get('ID'), params.get('ROLE'))
            elif params.get('role-unset'):
                self.requester.app_user_unset_role(params.get('ID'), params.get('ROLE'))
            elif params.get('delete'):
                self.show_system_reboot_info()
                self.requester.app_user_delete(params.get('ID'))
        elif params.get('communication'):
            if params.get('import'):
                self.show_system_reboot_info()
                self.requester.app_communication_import(params.get('--input'))
            elif params.get('list'):
                self.requester.app_communication_list()
            elif params.get('delete'):
                self.show_system_reboot_info()
                self.requester.app_communication_delete(params.get('ALIAS'))
        elif params.get('prefetch'):
            family_id = params.get('FAMILY_ID')
            uid = params.get('UID')
            pdi = params.get('--pdi')
            cert = None
            cert_path_or_value = params.get('--deviceIdErCert')
            if cert_path_or_value:
                if check_file_soft(cert_path_or_value):
                    cert = read_file(cert_path_or_value)
                else:
                    cert = cert_path_or_value

            if is_hex_x_bytes_long(uid, 8):
                self.requester.prefetch_string_devices(family_id, uid, pdi, cert)
            else:
                print('UID not in hex format or not having 8 bytes')
        elif params.get('prefetch-status'):
            family_id = params.get('FAMILY_ID')
            uid = params.get('UID')
            self.requester.prefetch_status(uid, family_id)


    @staticmethod
    def show_system_reboot_info():
        print("---------------------------------------------------------------------")
        print("Before next successful invocation please wait for service to reboot")
        print("---------------------------------------------------------------------")
