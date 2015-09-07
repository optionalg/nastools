#!/usr/bin/env python

__author__ = 'sstreiner'

import os.path
import re
import sys

def checknisnetgroup(netgroup):
    try:
        netgroupmatch = nis.match(netgroup, 'netgroup')
    except Exception as e:
        netgroupmatch = []
    if netgroupmatch:
        return True
    else:
        return False

def formatsecurity(strsecurity):
    securityline = ''
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
                securityline += values[0] + '=0.0.0.0/0'
        elif values[0] in ['actual', 'anon', 'nosuid', 'sec']:
    return hosts
    return strsecurity

def getexports(exportfile):
    commentline = re.compile('^#.*')
    emptyline = re.compile('^$')
    exports = []
    with open(exportfile) as f:
        exportsraw = [line.strip() for line in f]
    for line in exportsraw:
        if not commentline.match(line) and not emptyline.match(line):
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

    exports = getexports(exportfile)
    print(exports)
