#!/usr/bin/env python

__author__ = 'sstreiner'

import os.path
import re
import sys
from libcdotmigration import libcdotmigration as libcdot


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

    exports = libcdot.getexports(exportfile)
    exportsbyhost = {}
    hosts = []

    for elem in sorted(exports):
        exportpath = elem[0]
        if exportpath not in exports:
            exports.append(exportpath)
        exporthosts = []
        try:
            exporthosts = libcdot.gethostsinsecurity(elem[1])
        except Exception as e:
            sys.stderr.write("#ERROR: %s %s\n" % (exportpath, str(e)))
        for host in exporthosts:
            if host not in hosts:
                hosts.append(host)
            if host not in exportsbyhost:
                exportsbyhost[host] = [exportpath]
            else:
                exportsbyhost[host].append(exportpath)

    regexat = re.compile('^@')
    for host in hosts:
        if regexat.match(host):
            host = host[1:]

        if libcdot.checkipaddr(host):
            hostexists = True
        elif libcdot.checknetwork(host):
            hostexists = True
        elif libcdot.checknishosts(host):
            hostexists = True
        elif libcdot.checknisnetgroup(host):
            hostexists = True
        elif libcdot.checkdns(host):
            hostexists = True
        else:
            hostexists = False

        if not hostexists:
            print('%s %s' % (host, exportsbyhost[host]))
