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

import OpenSSL
import copy
import json
import logging
import pkg_resources
import requests
from Modules.Utilities import check_file, show_output, read_file
from os import environ
from packaging import version


class PassPhraseError(Exception):
    pass


class Requester:
    finish_on_error = True
    session = None
    urllib3_version_passwd_unsupported = "1.25.3"
    urllib3_name = "urllib3"

    def __init__(self, is_debug, service_url, service_port, certificate, cert_key, cert_ca, system_proxy):
        self.debug_enabled = is_debug
        self.service_url = service_url
        self.service_port = service_port
        self.certificate = certificate
        self.cert_key = cert_key
        self.cert_ca = cert_ca
        self.use_system_proxy = system_proxy

        if is_debug:
            self.enable_debug()

    def enable_debug(self):
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1

        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    def passphrase_callback_func(event, rwflag):
        raise PassPhraseError("Encrypted private key is not supported")

    def perform_request(self, method, url, payload=None, headers=None, silent=False, files=None, non_auth=False):
        if headers is None:
            headers = {
                'Cache-Control': "no-cache",
            }

        self.session = requests.Session()
        check_file(self.cert_ca)
        self.session.verify = self.cert_ca

        if non_auth is False:
            check_file(self.certificate)
            check_file(self.cert_key)
            self.session.cert = (self.certificate, self.cert_key)

        if self.use_system_proxy and environ.get("HTTPS_PROXY"):
            self.session.proxies = {'https': environ.get("HTTPS_PROXY")}

        try:
            # for encrypted private keys, in the previous version of 'urllib3' OpenSSL’s built-in password prompting
            # mechanism was used. Since version 1.25.3 'urllib3' requires that password is passed as a parameter,
            # which is not supported by 'requests' library
            if non_auth is False and version.parse(pkg_resources.get_distribution(self.urllib3_name).version) >= \
            version.parse(self.urllib3_version_passwd_unsupported):
                OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, read_file(self.cert_key),
                                               self.passphrase_callback_func)

            address = '{}://{}:{}{}'.format('https', str(self.service_url), int(self.service_port), str(url))
            req = requests.Request(method, address, headers, files, payload)
            prepared_request = self.session.prepare_request(req)
            res = self.session.send(prepared_request)

            if not silent:
                print('---------------------')
                print("Status: {} {}".format(res.status_code, res.reason))
                print('---------------------')

                if 'X-Total-Count' in res.headers:
                    print("Total items count: {}".format(res.headers.get('X-Total-Count')))
                    if 'Link' in res.headers:
                        print("Links: {}".format(res.headers.get('Link')))
                    print('---------------------')

            data = copy.copy(res.content)
            data_str = res.text

            if not silent:
                if res.status_code == requests.codes.ok and len(data_str) > 0:
                    show_output(data_str)
                elif res.status_code == requests.codes.ok:
                    print('Command succeeded!')
                elif res.status_code == requests.codes.created and len(data_str) > 0:
                    show_output(data_str)
                else:
                    parsed = json.loads(data_str)
                    print(json.dumps(parsed["status"], indent=2, sort_keys=False))

            if res.status_code == requests.codes.ok:
                return data
            else:
                return None
        except Exception as error:
            print("Error occurred:", error)
            if self.finish_on_error:
                exit(1)
        finally:
            self.session.close()

    @staticmethod
    def prepare_payload_from_file(input_file):
        check_file(input_file)
        with open(input_file, encoding='utf8') as file:
            payload = file.read().strip()
        return payload

    @staticmethod
    def prepare_binary_payload_from_file(input_file):
        check_file(input_file)
        with open(input_file, 'rb') as file:
            payload = file.read()
        return payload

    @staticmethod
    def get_query(query):
        if query is not None and len(query) > 0:
            query = '?%s' % query
        else:
            query = ''

        return query

    @staticmethod
    def get_json_headers():
        return {
            'Cache-Control': "no-cache",
            'Content-Type': "application/json"
        }

    @staticmethod
    def save_data_to_file(output_path, data):
        if output_path is not None and data is not None:
            out = open(output_path, 'w')
            out.write(data.decode("utf-8"))
            out.close()
            print("\nSaved output to file: {}".format(output_path))

    def health(self, is_detailed):
        url = "/health"
        if is_detailed:
            url += "/sla"

        self.perform_request('GET', url, non_auth=True)

    def get_service_import_public_key(self, output_path, silent=False):
        data = self.perform_request('GET', '/config/v1/import-key', silent=silent)
        self.save_data_to_file(output_path, data)
        return data

    def create_import_key(self):
        self.perform_request('POST', '/init/v1/import-key')

    def delete_import_key(self):
        self.perform_request('DELETE', '/init/v1/import-key')

    def create_sealing_key(self):
        self.perform_request('POST', '/init/v1/sealing-key')

    def rotate_sealing_key(self):
        self.perform_request('POST', '/init/v1/sealing-key/rotate')

    def list_sealing_keys(self):
        self.perform_request('GET', '/init/v1/sealing-key')

    def backup_sealing_key(self, import_pub_key, output_path):
        data = self.perform_request('POST', '/init/v1/sealing-key/backup', import_pub_key, self.get_json_headers())
        self.save_data_to_file(output_path, data)

    def restore_sealing_key(self, encrypted_sealing_key):
        self.perform_request('POST', '/init/v1/sealing-key/restore', encrypted_sealing_key, self.get_json_headers())

    def create_signing_key(self):
        self.perform_request('POST', '/init/v1/signing-key')

    def list_signing_keys(self):
        self.perform_request('GET', '/init/v1/signing-key/list', None, self.get_json_headers())

    def get_service_signing_key_internal(self, signing_key_id):
        return self.perform_request('GET', '/init/v1/signing-key/%d' % int(signing_key_id))

    def get_signing_key(self, signing_key_id, output_path):
        data = self.get_service_signing_key_internal(signing_key_id)
        self.save_data_to_file(output_path, data)

    def upload_signing_key(self, signing_key_id, single_chain_input_file, multi_chain_input_file):
        files = {'singleRootChain': self.prepare_binary_payload_from_file(single_chain_input_file),
                 'multiRootChain': self.prepare_binary_payload_from_file(multi_chain_input_file)}
        self.perform_request('POST', '/init/v1/signing-key/upload/%d' % int(signing_key_id), files=files)

    def activate_signing_key(self, signing_key_id):
        self.perform_request('POST', '/init/v1/signing-key/activate/%d' % int(signing_key_id))

    def add_root_signing_pub_key(self, input_file):
        files = {'file': self.prepare_binary_payload_from_file(input_file)}
        self.perform_request('POST', '/init/v1/root-signing-key', files=files)

    def rotate_context_key(self):
        self.perform_request('POST', '/init/v1/context-key/rotate')

    def create_configuration(self, payload):
        self.perform_request('POST', '/config/v1/configuration', payload, self.get_json_headers())

    def list_configuration(self):
        self.perform_request('GET', '/config/v1/configuration', None, self.get_json_headers())

    def get_configuration(self, config_id):
        self.perform_request('GET', '/config/v1/configuration/{}'.format(config_id), None, self.get_json_headers())

    def update_configuration(self, payload, config_id):
        self.perform_request('PUT', '/config/v1/configuration/{}'.format(config_id), payload, self.get_json_headers())

    def delete_configuration(self, config_id):
        self.perform_request('DELETE', '/config/v1/configuration/{}'.format(config_id))

    def app_user_create_initial(self, token, input_file, output_path):
        files = {'file': ('data.pem', open(input_file, 'rb'))}
        data = self.perform_request('POST', '/user-init/v1/%s' % str(token), files=files, headers=None, non_auth=True)
        self.save_data_to_file(output_path, data)

    def app_user_create(self, input_file, output_path):
        files = {'file': ('data.pem', open(input_file, 'rb'))}
        data = self.perform_request('POST', '/user/v1/manage', files=files, headers=None)
        self.save_data_to_file(output_path, data)

    def app_user_list(self):
        self.perform_request('GET', '/user/v1/manage', None, self.get_json_headers())

    def app_user_set_role(self, user_id, role):
        payload = '{"role":"%s"}' % role
        self.perform_request('POST', '/user/v1/manage/%d/role/set' % int(user_id), payload, self.get_json_headers())

    def app_user_unset_role(self, user_id, role):
        payload = '{"role":"%s"}' % role
        self.perform_request('POST', '/user/v1/manage/%d/role/unset' % int(user_id), payload, self.get_json_headers())

    def app_user_delete(self, user_id):
        self.perform_request('DELETE', '/user/v1/manage/%d' % int(user_id), None, self.get_json_headers())

    def app_communication_import(self, input_file):
        files = {'file': ('cert.pem', open(input_file, 'rb'))}
        self.perform_request('POST', '/user/v1/trusted-certificate/manage', files=files, headers=None)

    def app_communication_list(self):
        self.perform_request('GET', '/user/v1/trusted-certificate/manage', None, self.get_json_headers())

    def app_communication_delete(self, alias):
        self.perform_request('DELETE', '/user/v1/trusted-certificate/manage/%s' % str(alias), None, self.get_json_headers())

    def prefetch_string_devices(self, family_id, uid, pdi, cert):
        content = []
        item = {}
        if family_id is not None:
            item['familyId'] = family_id
        if uid is not None:
            item['uid'] = uid
        if pdi is not None:
            item['pdi'] = pdi
        if cert is not None:
            item['deviceIdEr'] = cert

        content.append(item)
        self.perform_request('POST', '/prov/v1/prefetch/devices', json.dumps(content), self.get_json_headers())

    def prefetch_status(self, device_id, family_id):
        if device_id is not None and family_id is not None:
            self.perform_request('GET', '/prov/v1/prefetch/status?familyId=%s&uid=%s'
                                 % (str(family_id), str(device_id)), None, headers=None)
        else:
            self.perform_request('GET', '/prov/v1/prefetch/status', None, headers=None)
