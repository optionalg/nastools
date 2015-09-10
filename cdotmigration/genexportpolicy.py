#!/usr/bin/env python

__author__ = 'sstreiner'

import os.path
import sys
from collections import OrderedDict
from libcdotmigration import libcdotmigration as libcdot


def printusage():
    print('Usage: %s EXPORTFILE VSERVER' % sys.argv[0])


if __name__ == "__main__":
    if not len(sys.argv) > 2:
        printusage()
        sys.exit(1)
    if not os.path.isfile(sys.argv[1]):
        sys.stderr.write('#ERROR: %s is not a file!\n' % sys.argv[1])
        sys.exit(1)
    else:
        exportfile = sys.argv[1]
        vserver = sys.argv[2]

    exports = libcdot.getexports(exportfile)
    exportpolicys = {}
    permissions = {}
    for elem in sorted(exports):
        try:
            policyname = libcdot.getexportpolicy(elem[0])
            volumename = elem[0].split('/')[2]
            security = libcdot.getpermissionsbyhost(libcdot.getsecurity(elem[1]))
            hosts = libcdot.gethostsinsecurity(elem[1])
            if libcdot.isvolume(elem[0]):
                exportpolicys[policyname] = 'volume modify -vserver %s -volume %s -policy %s' % (
                    vserver, volumename, policyname)
                if policyname not in permissions:
                    permissions[policyname] = security
                else:
                    permissions[policyname].update(libcdot.updatesecurity(permissions[policyname], security))
            else:
                qtree = elem[0].split('/')[3]
                if volumename not in permissions:
                    permissions[volumename] = OrderedDict()
                    exportpolicys[volumename] = 'volume modify -vserver %s -volume %s -policy %s' % (
                        vserver, volumename, volumename)
                permissions[volumename].update(
                    libcdot.updatesecurity(permissions[volumename], libcdot.getpermissionsbyhost([('ro', hosts)])))
                exportpolicys[policyname] = 'qtree modify -vserver %s -volume %s -qtree %s -export-policy %s' % (
                    vserver, volumename, qtree, policyname)
                if policyname not in permissions:
                    permissions[policyname] = security
                else:
                    permissions[policyname].update(libcdot.updatesecurity(permissions[policyname], security))
        except Exception as e:
            sys.stderr.write('#%s\n' % elem)
            sys.stderr.write('#%s\n' % str(e))
    for policyname in sorted(permissions):
        print('export-policy create -vserver %s -policyname %s' % (vserver, policyname))
        libcdot.printexportpolicyrules(vserver, policyname, permissions[policyname])
    for exportpolicy in exportpolicys:
        print(exportpolicys[exportpolicy])

