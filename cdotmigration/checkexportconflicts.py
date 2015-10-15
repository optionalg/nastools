#!/usr/bin/env python

__author__ = 'sstreiner'

import os.path
import sys
from libcdotmigration import libcdotmigration as libcdot


def printusage():
    print('Usage: %s EXPORTFILE' % sys.argv[0])

def getsecurityng(strsecurity):
    security = {}
    elements = strsecurity.split(',')
    if not strsecurity.find('rw,') and \
            not strsecurity.find('rw=') and \
            not strsecurity.find('ro,') and \
            not strsecurity.find('ro='):
        security['rw'] = ['0.0.0.0/0']
    for element in elements:
        values = element.split('=')
        if len(values) < 2:
            security[values[0]] = ['0.0.0.0/0']
        else:
            if values[0] == 'ro' or values[0] == 'rw' or values[0] == 'root':
                if values[0] in security:
                    security[values[0]].append(values[1].split(':'))
                else:
                    security[values[0]] = values[1].split(':')
    return security

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
    folderexports = []
    for elem in sorted(exports):
        parts = elem[0].split('/')
        if len(parts) > 3 and parts[3]:
            folderexports.append(elem)

    exports_by_qtree = {}
    hosts_by_qtree = {}
    for elem in sorted(folderexports):
        parts = elem[0].split('/')
        qtreepath = '/%s/%s/%s' % (parts[1],parts[2], parts[3])
        secline = getsecurityng(elem[1])
        try:
            hosts = libcdot.gethostsinsecurity(elem[1])
            if qtreepath not in exports_by_qtree:
                exports_by_qtree[qtreepath] = {}
            exports_by_qtree[qtreepath].update({elem[0]:secline})
            if qtreepath not in hosts_by_qtree:
                hosts_by_qtree[qtreepath] = []
            for host in hosts:
                if host not in hosts_by_qtree[qtreepath]:
                    hosts_by_qtree[qtreepath].append(host)
        except Exception as e:
            sys.stderr.write('#ERROR: %s %s' %(elem[0], str(e)))

    for qtree in hosts_by_qtree:
        for host in hosts_by_qtree[qtree]:
            ro_count = 0
            rw_count = 0
            for subfolder in exports_by_qtree[qtree]:
                # catch false positives
                duplicate_count = 0
                if 'ro' in exports_by_qtree[qtree][subfolder]:
                    if host in exports_by_qtree[qtree][subfolder]['ro']:
                        ro_count += 1
                        duplicate_count += 1
                if 'rw' in exports_by_qtree[qtree][subfolder]:
                    if host in exports_by_qtree[qtree][subfolder]['rw']:
                        rw_count += 1
                        duplicate_count += 1
                # catch false positives
                if duplicate_count == 2:
                    ro_count -= 1
            if ro_count >=1 and rw_count >= 1:
                print("%s %s" %(qtree, host))

