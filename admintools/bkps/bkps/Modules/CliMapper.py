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


from Modules.Utilities import *


class CliMapper:
    help_service_import_key = "service-import-key > create | delete"
    help_sealing_key = "sealing-key > create | rotate | list\n" \
                       "sealing-key > backup (-i FILE | --input FILE) (-o FILE | --output FILE)\n" \
                       "sealing-key > restore (-i FILE | --input FILE)"
    help_context_key = "context-key rotate"
    help_signing_key = "signing-key > create | list | get (--id ID) [-o FILE | --output FILE]\n" \
                       "signing-key > upload (--id ID) (--single SINGLE_FILE) (--multi MULTI_FILE) | activate (--id ID)"
    help_root_signing_key = "root-signing-key > add (-i FILE | --input FILE)"
    help_service_import_pubkey = "service-import-pub-key > get [-o FILE | --output FILE]"
    help_configuration = "configuration > create (--id ID) (--interactive | --json (-i FILE | --input FILE))\n" \
                         "configuration > update (--id ID) (--interactive | --json (-i FILE | --input FILE))\n" \
                         "configuration > list | get (--id ID) | delete (--id ID)"
    help_communication = "communication > import [-i FILE | --input FILE] | list | delete [--id ALIAS]"
    help_users = "users > create [-i FILE | --input FILE] [-o FILE | --output FILE] " \
                 "| initial-create (--token TOKEN) [-i FILE | --input FILE] [-o FILE | --output FILE] | list " \
                 "| role-set [--id ID] [--role ROLE] | role-unset [--id ID] [--role ROLE] | delete [--id ID]"

    available_user_roles = None

    def __init__(self, available_user_roles):
        self.available_user_roles = available_user_roles

    def get_requests_params(self, variable):
        params = {}

        if assign_params_value(params, 'health', variable):
            details = input('Show details? (Y/N): ')
            if details.upper() == 'Y':
                assign_params_value(params, '--detailed')

        if assign_params_value(params, 'service-import-key', variable):
            variable = self.section_loop_short('request::service-import-key', self.help_service_import_key,
                                               ['create', 'delete'])
            if variable is not None:
                assign_params_value(params, 'create', variable)
                assign_params_value(params, 'delete', variable)
            else:
                return params

        if assign_params_value(params, 'sealing-key', variable):
            variable = self.section_loop_short('request::sealing-key', self.help_sealing_key,
                                               ['create', 'rotate', 'list', 'backup', 'restore'])
            if variable is not None:
                assign_params_value(params, 'create', variable)
                assign_params_value(params, 'rotate', variable)
                assign_params_value(params, 'list', variable)
                if assign_params_value(params, 'backup', variable):
                    params['--input'] = input_file_path('BKPS Service Import Pub Key PEM file')
                    variable = input('Enter output path to Encrypted Sealing Backup Key JSON file: ')
                    params['--output'] = variable
                    assign_params_value(params, 'list', variable)
                if assign_params_value(params, 'restore', variable):
                    params['--input'] = input_file_path('Encrypted Sealing Backup Key JSON file')
            else:
                return params

        if assign_params_value(params, 'context-key', variable):
            variable = self.section_loop_short('request::context-key', self.help_context_key, ['rotate'])
            if variable is not None:
                assign_params_value(params, 'rotate', variable)
            else:
                return params

        if assign_params_value(params, 'signing-key', variable):
            variable = self.section_loop_short('request::signing-key', self.help_signing_key,
                                               ['create', 'get', 'list', 'upload', 'activate'])
            if variable is not None:
                assign_params_value(params, 'create', variable)
                if assign_params_value(params, 'get', variable, 'Enter ID', 'ID', 'NUMBER'):
                    details = input('Save output to file? (Y/N): ')
                    if details.upper() == 'Y':
                        variable = input('Enter output path: ')
                        params['--output'] = variable
                assign_params_value(params, 'list', variable)

                if assign_params_value(params, 'upload', variable, 'Enter ID', 'ID', 'NUMBER'):
                    params['SINGLE_FILE'] = input_file_path('single root chain QKY')
                    params['MULTI_FILE'] = input_file_path('multi root chain QKY')

                assign_params_value(params, 'activate', variable, 'Enter ID', 'ID', 'NUMBER')
            else:
                return params

        if assign_params_value(params, 'root-signing-key', variable):
            variable = self.section_loop_short('request::root-signing-key', self.help_root_signing_key, ['add'])
            if variable is not None:
                assign_params_value(params, 'add', variable, 'Provide input path', '--input', 'FILE')
            else:
                return params

        if assign_params_value(params, 'service-import-pub-key', variable):
            variable = self.section_loop_short('request::service-import-pub-key', self.help_service_import_pubkey,
                                               ['get'])
            if variable is not None:
                assign_params_value(params, 'get', variable, 'Provide output path', '--output')
            else:
                return params

        if assign_params_value(params, 'configuration', variable):
            variable = self.section_loop_short('request::configuration', self.help_configuration,
                                               ['list', 'create', 'get', 'update', 'delete'])
            if variable is not None:
                assign_params_value(params, 'list', variable)
                assign_params_value(params, 'get', variable, 'Enter ID', 'ID', 'NUMBER')
                assign_params_value(params, 'delete', variable, 'Enter ID', 'ID', 'NUMBER')
                if assign_params_value(params, 'create', variable) or assign_params_value(params, 'update', variable):
                    config_type = input_req_configuration_import_types()
                    assign_params_value(params, config_type)
                    if config_type == '--json':
                        params['--input'] = input_file_path('JSON configuration')

            else:
                return params

        if assign_params_value(params, 'communication', variable):
            variable = self.section_loop_short('request::communication', self.help_communication,
                                               ['import', 'list', 'delete'])
            if variable is not None:
                assign_params_value(params, 'import', 'Provide input path', '--input', 'FILE')
                assign_params_value(params, 'list', variable)
                assign_params_value(params, 'delete', variable, 'Enter ID', 'ALIAS')
            else:
                return params

        if assign_params_value(params, 'user', variable):
            variable = self.section_loop_short('request::user', self.help_users,
                                               ['create', 'initial-create', 'list', 'role-set', 'role-unset', 'delete'])
            if variable is not None:
                if assign_params_value(params, 'create', variable, 'Provide input path', '--input', 'FILE'):
                    details = input('Save output to file? (Y/N): ')
                    if details.upper() == 'Y':
                        variable = input('Enter output path: ')
                        params['--output'] = variable

                if assign_params_value(params, 'initial-create', variable, 'Provide input path', '--input', 'FILE'):
                    details = input('Save output to file? (Y/N): ')
                    if details.upper() == 'Y':
                        variable = input('Enter output path: ')
                        params['--output'] = variable

                assign_params_value(params, 'list', variable)

                if assign_params_value(params, 'role-set', variable, 'Enter ID', 'ID', 'NUMBER'):
                    params['ROLE'] = self.input_role()

                if assign_params_value(params, 'role-unset', variable, 'Enter ID', 'ID', 'NUMBER'):
                    params['ROLE'] = self.input_role()

                assign_params_value(params, 'delete', variable, 'Enter ID', 'ID', 'NUMBER')
            else:
                return params

        if assign_params_value(params, 'prefetch', variable):
            params['UID'] = input('Enter HEX encoded deviceId : ')
            params['FAMILY_ID'] = input('Device family identifier (as hex, eg. 0x0A) : ')
            params['PDI'] = input('Platform device identifier (as hex, eg. 0x0A) '
                                  '[only for SM, leave empty for other platforms]: ')
            params['CERT_FILE'] = input('Path to enrollment deviceID in PEM format or PEM in plaintext'
                                   '[only for FM/DM, leave empty for other platforms]: ')

        if assign_params_value(params, 'prefetch-status', variable):
            params['UID'] = input('Enter HEX encoded deviceId [leave empty for status of all devices]: ')
            params['FAMILY_ID'] = input('Device family identifier (as hex, eg. 0x0A) '
                                        '[leave empty for status of all devices]: ')

        return params

    @staticmethod
    def section_loop_short(section, help_content, valid_options_array):
        while True:
            variable = input('Enter {} command (or type "help"): '.format(section))

            if variable == 'up':
                print('Moved back to previous section')
                break
            elif variable == 'help':
                print(help_content)
                continue
            elif variable == 'exit':
                print('Work finished.')
                exit(0)
            elif variable in valid_options_array:
                return variable

    def input_role(self):
        while True:
            usr_input = input('Enter ROLE (' + self.available_user_roles + '): ')
            to_verify = usr_input.upper()
            if to_verify in (self.available_user_roles.split(",")):
                return to_verify
