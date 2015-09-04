#!/usr/bin/env python

__author__ = 'sstreiner'

import os.path
import re
import socket
import sys
import nis

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

def checknisnetgroup(netgroup):
    try:
        netgroupmatch = nis.match(netgroup, 'netgroup')
    except Exception as e:
        netgroupmatch = []
    if netgroupmatch:
        return True
    else:
        return False

def checkdns(host):
    try:
        ipaddrs = []
        dnsraw = socket.getaddrinfo(host, 0)
        for addr in dnsraw:
            ipaddrs.append(addr[-1][0])
    except Exception as e:
        ipaddrs = []
    if ipaddrs:
        return True
    else:
        return False

def getexports(exportsfile):
    commentline = re.compile('^#.*')
    emptyline = re.compile('^$')
    exports = []
    with open(exportfile) as f:
        exportsraw = [line.strip() for line in f]
    for line in exportsraw:
        if not commentline.match(line) and not emptyline.match(line):
            exports.append(line)
    return exports

def gethostsinsecurity(strsecurity):
    hosts = []
    elements = strsecurity.split(',')
    for element in elements:
        values = element.split('=')
        if values[0] in ['ro', 'rw', 'root']:
            if len(values) > 1:
                hostsraw = values[1].split(':')
                for host in hostsraw:
                    if host not in hosts:
                        hosts.append(host)
            else:
                raise Exception('#ERROR: Export Line not valid (%s)\n' % strsecurity)
    return hosts

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

    exports = getexports(exportfile)
    emptyline = re.compile('^$')
    exportsbyhost = {}
    hosts = []

    with open(exportfile) as f:
        exportsraw = [line.strip() for line in f]

    for line in exportsraw:
        if not commentline.match(line) and not emptyline.match(line):
            exports.append(line)

    for elem in sorted(exports):
        parts = elem.split()
        exportpath = parts[0]
        if not exportpath in exports:
            exports.append(exportpath)
        exporthosts = []
        try:
            exporthosts = gethostsinsecurity(parts[1])
        except Exception as e:
            sys.stderr.write("%s\n" % str(e))
        for host in exporthosts:
            if not host in hosts:
                hosts.append(host)
            if not exportsbyhost.has_key(host):
                exportsbyhost[host] = [exportpath]
            else:
                exportsbyhost[host].append(exportpath)

    for host in hosts:
        if checknishosts(host):
            hostexists = True
        elif checknisnetgroup(host):
            hostexists = True
        elif checkdns(host):
            hostexists = True
        else:
            hostexists = False

        if not hostexists:
            print('%s %s' %(host, exportsbyhost[host]))

