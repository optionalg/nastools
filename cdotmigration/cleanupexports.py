#!/usr/bin/env python

__author__ = 'sstreiner'

import os.path
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

    exports = libcdot.getexportswithcomments(exportfile)
    for export in exports:
        if isinstance(export, list):
            print('%s %s %s' % (export[0], '\t' * abs(6 - export[0].count('/')), libcdot.formatsecurity(export[1])))
        else:
            print(export)
