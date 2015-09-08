#!/usr/bin/env python

__author__ = 'sstreiner'

import os.path
import nis
import re
import socket
import sys


def checkdns(host):
    try:
        ipaddrs = []
        dnsraw = socket.gethostbyaddr(host)
        for addr in dnsraw:
            ipaddrs.append(addr[-1][0])
    except Exception as e:
        ipaddrs = []
    if ipaddrs:
        return True
    else:
        return False


def checknisnetgroup(netgroup):
    try:
        netgroupmatch = nis.match(netgroup, 'netgroup')
    except Exception as e:
        netgroupmatch = []
    if netgroupmatch:
        return True
    else:
        return False


def checknishosts(host):
    try:
        nisdomain = nis.get_default_domain()
        hostsmatch = nis.match(host, 'hosts')
        if not hostsmatch:
            hostsmatch = nis.match(host + '.' + nisdomain, 'hosts')
    except Exception as e:
        hostsmatch = []
    if hostsmatch:
        return True
    else:
        return False


def formatsecurity(strsecurity):
    securityline = '-'
    strsecurity = re.sub(r'^-', '', strsecurity)
    elements = strsecurity.split(',')
    regexip = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    regexnet = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
    regexat = re.compile('^@')
    for element in elements:
        values = element.split('=')
        if values[0] in ['ro', 'rw', 'root']:
            securityline += values[0]
            if len(values) > 1:
                securityline += '='
                hostsraw = values[1].split(':')
                for host in hostsraw:
                    if regexat.match(host):
                        host = host[1:]

                    if checknisnetgroup(host):
                        securityline += '@' + host + ':'
                    elif checknishosts(host) or checkdns(host):
                        securityline += host + ':'
                    elif regexip.match(host) or regexnet.match(host):
                        securityline += host + ':'
                    else:
                        sys.stderr.write("#ERROR: removed host/netgroup %s from security!\n" % host)
                securityline = re.sub(r':$', '', securityline)
        else:
            securityline += values[0]
            if values[1]:
                securityline += '=' + values[1]
        securityline += ','
    securityline = re.sub(r',$', '', securityline)
    return securityline

def getexportswithcomments(exportfile):
    commentline = re.compile('^#.*')
    emptyline = re.compile('^$')
    exports = []
    with open(exportfile) as f:
        exportsraw = [line.strip() for line in f]
    for line in exportsraw:
        if not commentline.match(line) and not emptyline.match(line):
            exports.append(line.split())
        elif commentline.match(line):
            exports.append(line)
    return exports

def printusage():
    print('Usage: %s EXPORTFILE' % sys.argv[0])

if __name__ == "__main__":
    if not len(sys.argv) > 1:
        printusage()
        sys.exit(1)
    if not os.path.isfile(sys.argv[1]):
        sys.stderr.write("#ERROR: %s is not a file!\n" % sys.argv[1])
        sys.exit(1)
    else:
        exportfile = sys.argv[1]

    exports = getexportswithcomments(exportfile)
    for export in exports:
        if isinstance(export, list):
            print('%s %s %s' % (export[0], '\t' * abs(6 - export[0].count('/')), formatsecurity(export[1])))
        else:
            print(export)

