#!/usr/bin/env python
# Description:
#   Multithreaded tool to scan for Webclient service "DAV RPC SERVICE" named pipe
#
# Author:
#   pixis (@hackanddo)
#
# Acknowledgments:
#   @tifkin_ https://twitter.com/tifkin_/status/1419806476353298442


import argparse
import sys
import os

from impacket.examples.utils import parse_target
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import SMB2_DIALECT_21, SMB2_DIALECT_311

from webclientservicescanner.core import ThreadPool
from webclientservicescanner.utils import get_targets, banner, validate_credentials


def main():
    os.system('color')
    print(banner())
    parser = argparse.ArgumentParser(add_help=True, description="SMB client implementation.")

    parser.add_argument('target', action='store',
                        help='[[domain/]username[:password]@]<target address or IP range or IP list file>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-smb-version', choices=['1', '2', '3'], help='SMB version to negotiate')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication ')
    group.add_argument('-no-validation', action="store_true", help='Bypass credentials validation')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')

    group = parser.add_argument_group('parallelization')

    group.add_argument('-threads', action='store', default='256', metavar="threads", help='Max threads')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    domain, username, password, address = parse_target(options.target)

    targets = get_targets([address])

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.smb_version is not None:
        smb_versions = (
            (SMB_DIALECT, '1'),
            (SMB2_DIALECT_21, '2'),
            (SMB2_DIALECT_311, '3')
        )
        options.smb_version = [version[0] for version in smb_versions if version[1] == options.smb_version][0]

    if not options.no_validation:
        ret = validate_credentials(username, domain, password, options.dc_ip, options.k, lmhash, nthash, options.aesKey, options.debug)
        if not ret:
            return False

    threadPool = ThreadPool(
        targets,
        options.smb_version,
        username,
        password,
        domain,
        lmhash,
        nthash,
        options.aesKey,
        options.dc_ip,
        options.k,
        int(options.threads),
        options.debug
    )

    threadPool.run()


if __name__ == "__main__":
    main()
