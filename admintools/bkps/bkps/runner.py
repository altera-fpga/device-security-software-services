#!/usr/bin/python3

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


"""Black Key Provisioning Service (BKPS)

Usage:
  runner.py health [--detailed]
  runner.py service-import-key (create | delete)
  runner.py sealing-key (create | rotate | list)
  runner.py sealing-key (backup (-i FILE | --input FILE) (-o FILE | --output FILE))
  runner.py sealing-key (restore (-i FILE | --input FILE))
  runner.py signing-key (create | list | get (--id ID) [-o FILE | --output FILE])
  runner.py signing-key (upload (--id ID) (--single SINGLE_FILE) (--multi MULTI_FILE) | activate (--id ID))
  runner.py root-signing-key add (-i FILE | --input FILE)
  runner.py service-import-pub-key (get [-o FILE | --output FILE])
  runner.py configuration (create | update (--id ID)) (--interactive | --json (-i FILE | --input FILE))
  runner.py configuration (list | get (--id ID) | delete (--id ID))
  runner.py prefetch (--familyId FAMILY_ID) (--deviceId UID) [--pdi PDI] [--deviceIdErCert CERT_FILE]
  runner.py prefetch-status [--deviceId UID] [--familyId FAMILY_ID]
  runner.py context-key rotate
  runner.py communication (import [-i FILE | --input FILE] | list | delete [--id ALIAS])
  runner.py user (create [-i FILE | --input FILE] [-o FILE | --output FILE] | initial-create (--token TOKEN) [-i FILE | --input FILE] [-o FILE | --output FILE])
  runner.py user (list | role-set [--id ID] [--role ROLE] | role-unset [--id ID] [--role ROLE] | delete [--id ID])
  runner.py (-h | --help)
  runner.py --version
  runner.py

Arguments:
  ROLE   user role from available [ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_PROGRAMMER, ROLE_VIEWER]
  ID     signing key id or configuration id or user id
  FILE   path to file
  TOKEN  Token for creating initial user.
  QUERY  query parameters (inside double quotes if using '&' to specify multiple params, e.g. "page=0&size=50&sort=id,desc")
  SINGLE_FILE    path to single root customer certificate chain in QKY format (S10)
  MULTI_FILE     path to multi root customer certificate chain in QKY format (Agilex)
  FAMILY_ID     device family identifier (as hex, eg. 0x32, 0x34, 0x35)
  UID           hex encoded device id (eg. 0102030405060708)
  PDI           hex encoded platform device identifier (exists since SM)
  CERT_FILE     path to enrollment deviceID certificate in PEM format or PEM in plaintext\n

Options:
  -h --help                 Show this screen.
  --version                 Show version.
  --detailed                SLA version of health.
  --json                    JSON file mode of creating a configuration.
  --interactive             Interactive mode of creating a configuration.
  -i FILE --input FILE      Input file path.
  -o FILE --output FILE     Output file path.
  --pdi PDI                 Platform identifier.
  --deviceIdErCert CERT_FILE    Path to enrollment cert.
"""
from docopt import docopt

from Modules.Commands import Commands

if __name__ == '__main__':
    arguments = docopt(__doc__, version='BKPS #VERSION#')
    Commands().run(arguments)
