#!/usr/bin/env python
# Description:
#   Multithreaded tool to scan for Webclient service "DAV RPC SERVICE" named pipe
#
# Author:
#   pixis (@hackanddo)
#
# Acknowledgments:
#   @tifkin_ https://twitter.com/tifkin_/status/1419806476353298442


import os

from netaddr import IPRange, AddrFormatError, IPAddress, IPNetwork

from . import __version__


def banner():
    return "WebClient Service Scanner v{} - pixis (@hackanddo) - Based on @tifkin_ idea\n".format(__version__)


def parse_targets(target):
    """
    Parse provided targets
    :param target: Targets
    :return: List of IP addresses
    """
    if '-' in target:
        ip_range = target.split('-')
        try:
            t = IPRange(ip_range[0], ip_range[1])
        except AddrFormatError:
            try:
                start_ip = IPAddress(ip_range[0])

                start_ip_words = list(start_ip.words)
                start_ip_words[-1] = ip_range[1]
                start_ip_words = [str(v) for v in start_ip_words]

                end_ip = IPAddress('.'.join(start_ip_words))

                t = IPRange(start_ip, end_ip)
            except AddrFormatError:
                t = target
    else:
        try:
            t = IPNetwork(target)
        except AddrFormatError:
            t = target
    if type(t) == IPNetwork or type(t) == IPRange:
        return list(t)
    else:
        return [t.strip()]


def get_targets(targets):
    """
    Get targets from file or string
    :param targets: List of targets
    :return: List of IP addresses
    """
    ret_targets = []
    for target in targets:
        if os.path.exists(target):
            with open(target, 'r') as target_file:
                for target_entry in target_file:
                    ret_targets += parse_targets(target_entry)
        else:
            ret_targets += parse_targets(target)
    return [str(ip) for ip in ret_targets]
