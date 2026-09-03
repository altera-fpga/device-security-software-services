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


import copy
from Modules.CliMapper import CliMapper
from Modules.Utilities import *


class Commands:
    help_requests = """
    Usage:
        health [--detailed]
        service-import-key > create | delete
        sealing-key > backup (-i FILE | --input FILE) (-o FILE | --output FILE)
        sealing-key > restore (-i FILE | --input FILE)
        signing-key > create | list | get (--id ID) [-o FILE | --output FILE]
        signing-key > upload (--id ID) (--single SINGLE_FILE) (--multi MULTI_FILE) | activate (--id ID)
        root-signing-key add (-i FILE | --input FILE)
        service-import-pub-key (get [-o FILE | --output FILE])
        configuration > create | update (--id ID)) (--interactive | --json (-i FILE | --input FILE)
        configuration > list | get (--id ID) | delete (--id ID)
        prefetch (--familyId FAMILY_ID) (--deviceId UID) [--pdi PDI] [--deviceIdErCert CERT_FILE]
        prefetch-status [--deviceId UID] [--familyId FAMILY_ID]
        context-key rotate
        communication > import [-i FILE | --input FILE] | list | delete [--id ALIAS]
        user > create [-i FILE | --input FILE] [-o FILE | --output FILE] | initial-create [-i FILE | --input FILE] [-o FILE | --output FILE]
        user > list | role-set [--id ID] [--role ROLE] | role-unset [--id ID] [--role ROLE] | delete [--id ID]
        """

    available_user_roles = 'ROLE_SUPER_ADMIN,ROLE_ADMIN,ROLE_PROGRAMMER,ROLE_VIEWER'

    help = """Black Key Provisioning Service (BKPS)\n\n{0}\n
    Common:
        up
        exit\n
    Arguments:
        ROLE   user role from available [{1}]
        ID     user id
        FILE   path to file
        FAMILY_ID     device family identifier (as hex, eg. 0x32, 0x34, 0x35)
        QUERY  query parameters (inside double quotes if using '&' to specify multiple params, e.g. "page=0&size=50&sort=id,desc")
        UID    hex encoded device id (eg. 0102030405060708)
        PDI    hex encoded platform device identifier (exists since SM)
        CERT_FILE   path to enrollment deviceID certificate in PEM format or PEM in plaintext\n
    Options:
        -h --help     Show this screen.
        --version     Show version.
        --detailed    SLA version of health.
        -i FILE --input FILE    Input file path.
        -o FILE --output FILE    Output file path.
        --id ID     Configuration identifier
        --pdi PDI   Platform identifier
        --deviceIdErCert CERT_FILE  Path to enrollment cert or PEM cert in plaintext\n\n    """.format(help_requests, available_user_roles)

    config_table = {
        "service_url": None,
        "service_port": 8082,
        "certificate_key": None,
        "certificate": None,
        "certificate_ca": None,
        "debug": False,
        "system_proxy": True
    }

    valid_main_categories = [
        'health',
        'service-import-key',
        'sealing-key',
        'signing-key',
        'root-signing-key',
        'service-import-pub-key',
        'configuration',
        'context-key',
        'communication',
        'user',
        'prefetch',
        'prefetch-status'
    ]

    runner_cfg = os.path.dirname(os.path.realpath(__file__)) + '/../runner-config.json'

    requestMethodMapper = None
    config = None

    def __init__(self):
        pass

    def run(self, arguments):
        try:
            if is_command_docopt(self.valid_main_categories, arguments):
                self.handle_docopt_command(arguments)
            else:
                self.start_command_loop()
            pass
        except KeyboardInterrupt:
            print('\nWork finished.')
        except Exception as error:
            print("Error occurred:", error)

    def load_json_config(self):
        if not os.path.isfile(self.runner_cfg):
            sys.exit("File does not exist: {}".format(self.runner_cfg))

        with open(self.runner_cfg, encoding='utf8') as file:
            source = file.read().strip()

        return json.loads(source)

    def start_command_loop(self):
        while True:
            result = self.handle()
            if result:
                print('Work finished.')
                break

    def handle(self):
        argument = input('Choose main section/command (%s|help|exit): ' % '|'.join(self.valid_main_categories))

        if argument == 'help':
            self.show_help()
        elif argument == 'exit':
            return True
        else:
            self.choose_config()
            self.init_requests(False)
            self.section_loop('request', self.help_requests, CliMapper(self.available_user_roles).get_requests_params,
                              self.requestMethodMapper.request_methods, argument)

        return False

    def handle_docopt_command(self, arguments):
        self.config = self.load_json_config()
        if self.config['debug']:
            print('Parsed config:')
            print(json.dumps(self.config, indent=4, sort_keys=False))
            print('\nParsed arguments:')
            print(json.dumps(arguments, indent=4, sort_keys=False))
            print('')

        self.init_requests(True)
        self.requestMethodMapper.request_methods(arguments)

    def choose_config(self):
        if check_file_soft(self.runner_cfg) and input_config_type():
            self.config = self.load_json_config()
        else:
            self.config = self.provide_cfg_requests()

    def show_help(self):
        print(self.help)

    #
    #   MAIN CATEGORIES INITIALIZATION
    #

    def init_requests(self, is_finishing_on_error):
        from Modules.Requester import Requester
        from Modules.RequestMethodMapper import RequestMethodMapper
        requester = Requester(self.config['debug'], self.config['service_url'],
                              self.config['service_port'], self.config['certificate'],
                              self.config['certificate_key'], self.config['certificate_ca'],
                              self.config['system_proxy'])
        requester.finish_on_error = is_finishing_on_error
        self.requestMethodMapper = RequestMethodMapper(requester, self.config['debug'])

    #
    #   MAIN CATEGORIES LOOPS
    #

    @staticmethod
    def section_loop(section, help_content, params_parser, callback, initial_cmf=None):
        while True:
            if initial_cmf is not None:
                variable = initial_cmf
            else:
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
            else:
                callback(params_parser(variable))

    #
    #   DYNAMIC CONFIGURATION METHODS FOR SPECIFIC CATEGORIES
    #

    def provide_cfg_requests(self):
        params = copy.copy(self.config_table)
        params['service_url'] = input_string('Service URL', True)
        params['service_port'] = input_number('Service PORT', 8082)
        params['certificate'] = input_file_path('User Certificate')
        params['certificate_key'] = input_file_path('User Certificate Key')
        params['certificate_ca'] = input_file_path('CA Certificate')
        params['system_proxy'] = input_using_proxy()
        params['debug'] = input_debug_mode()
        return params
