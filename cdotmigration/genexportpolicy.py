#!/usr/bin/env python

__author__ = 'sstreiner'

import os.path
import re
import sys
from collections import OrderedDict


def getexportpolicy(strexport):
    exportraw = strexport.split('/')
    if isvolume(strexport):
        return exportraw[2]
    return exportraw[2] + '_' + exportraw[3]


def getexports(exportfile):
    commentline = re.compile('^#.*')
    emptyline = re.compile('^$')
    exports = []
    with open(exportfile) as f:
        exportsraw = [line.strip() for line in f]
    for line in exportsraw:
        if not commentline.match(line) and not emptyline.match(line):
            exports.append(line.split())
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
                if '0.0.0.0/0' not in hosts:
                    hosts.append('0.0.0.0/0')
    return hosts


def getpermissionsbyhost(security):
    permissions = {}
    for element in security:
        for host in element[1]:
            if host not in permissions:
                permissions[host] = []
            permissions[host].append(element[0])
    return OrderedDict(sorted(permissions.items(), key=lambda t: t[0]))


def getsecurity(strsecurity):
    security = []
    elements = strsecurity.split(',')
    if not strsecurity.find('rw,') and \
            not strsecurity.find('rw=') and \
            not strsecurity.find('ro,') and \
            not strsecurity.find('ro='):
        security.append(('rw', ['0.0.0.0/0']))
    for element in elements:
        values = element.split('=')
        if len(values) < 2:
            security.append((values[0], ['0.0.0.0/0']))
        else:
            if values[0] == 'ro' or values[0] == 'rw' or values[0] == 'root':
                security.append((values[0], values[1].split(':')))
    return security


def isvolume(strexport):
    if len(strexport.split('/')) > 3:
        return False
    return True


def printexportpolicyrules(vserver, policyname, security):
    rwexports = []
    roexports = []
    allnetsexports = []
    for host in security:
        if 'rw' in security[host]:
            rwrule = 'any'
        else:
            rwrule = 'never'
        if 'ro' in security[host] or rwrule == 'any':
            rorule = 'any'
        else:
            rorule = 'never'
        if 'root' in security[host]:
            superuser = 'any'
        else:
            superuser = 'none'
        if host == '0.0.0.0/0':
            allnetsexports.append(
                'export-policy rule create -vserver %s -policyname %s -clientmatch %s -protocol nfs -rorule %s '
                '-rwrule %s -superuser %s -ruleindex 1000' % (
                    vserver, policyname, host, rorule, rwrule, superuser))
        else:
            if rwrule == 'any':
                rwexports.append(
                    'export-policy rule create -vserver %s -policyname %s -clientmatch %s -protocol nfs -rorule %s '
                    '-rwrule %s -superuser %s' % (
                        vserver, policyname, host, rorule, rwrule, superuser))
            else:
                roexports.append(
                    'export-policy rule create -vserver %s -policyname %s -clientmatch %s -protocol nfs -rorule %s '
                    '-rwrule %s -superuser %s -ruleindex 500' % (
                        vserver, policyname, host, rorule, rwrule, superuser))
    for export in rwexports:
        print(export)
    for export in roexports:
        print(export)
    for export in allnetsexports:
        print(export)


def printusage():
    print('Usage: %s EXPORTFILE VSERVER' % sys.argv[0])


def updatesecurity(securityold, securitynew):
    for host in securitynew:
        if host in securityold:
            for security in securitynew[host]:
                if security not in securityold[host]:
                    securityold[host].append(security)
        else:
            securityold[host] = securitynew[host]
    return securityold


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

    exports = getexports(exportfile)
    exportpolicys = {}
    permissions = {}
    for elem in sorted(exports):
        try:
            policyname = getexportpolicy(elem[0])
            volumename = elem[0].split('/')[2]
            security = getpermissionsbyhost(getsecurity(elem[1]))
            hosts = gethostsinsecurity(elem[1])
            if isvolume(elem[0]):
                exportpolicys[policyname] = 'volume modify -vserver %s -volume %s -policy %s' % (
                    vserver, volumename, policyname)
                if policyname not in permissions:
                    permissions[policyname] = security
                else:
                    permissions[policyname].update(updatesecurity(permissions[policyname], security))
            else:
                qtree = elem[0].split('/')[3]
                if volumename not in permissions:
                    permissions[volumename] = OrderedDict()
                    exportpolicys[volumename] = 'volume modify -vserver %s -volume %s -policy %s' % (
                        vserver, volumename, volumename)
                permissions[volumename].update(
                    updatesecurity(permissions[volumename], getpermissionsbyhost([('ro', hosts)])))
                exportpolicys[policyname] = 'qtree modify -vserver %s -volume %s -qtree %s -export-policy %s' % (
                    vserver, volumename, qtree, policyname)
                if policyname not in permissions:
                    permissions[policyname] = security
                else:
                    permissions[policyname].update(updatesecurity(permissions[policyname], security))
        except Exception as e:
            sys.stderr.write('#%s\n' % elem)
            sys.stderr.write('#%s\n' % str(e))
    for policyname in sorted(permissions):
        print('export-policy create -vserver %s -policyname %s' % (vserver, policyname))
        printexportpolicyrules(vserver, policyname, permissions[policyname])
    for exportpolicy in exportpolicys:
        print(exportpolicys[exportpolicy])
