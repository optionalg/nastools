__author__ = 'sstreiner'

import re
import socket
import nis
import sys
from collections import OrderedDict


def checkdns(host):
    try:
        dnsraw = socket.gethostbyaddr(host)
        dns = dnsraw[2]
        if dns:
            return True
    except:
        return False


def checkipaddr(host):
    try:
        socket.inet_aton(host)
        return True
    except:
        return False


def checknetwork(host):
    address = host.split('/')
    if len(address) > 1:
        if checkipaddr(address[0]) and 0 <= int(address[1]) <= 32:
            return True
    else:
        return False


def checknisnetgroup(netgroup):
    try:
        netgroupmatch = nis.match(netgroup, 'netgroup')
    except:
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
    except:
        hostsmatch = []
    if hostsmatch:
        return True
    else:
        return False


def checknisnetgroup(netgroup):
    try:
        netgroupmatch = nis.match(netgroup, 'netgroup')
    except:
        netgroupmatch = []
    if netgroupmatch:
        return True
    else:
        return False


def formatsecurity(strsecurity):
    securityline = '-'
    strsecurity = re.sub(r'^-', '', strsecurity)
    elements = strsecurity.split(',')
    regexat = re.compile('^@')
    regexnohosts = re.compile('^.*=$')
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

                    if checkipaddr(host) or checknetwork(host):
                        securityline += host + ':'
                    elif checknisnetgroup(host):
                        securityline += '@' + host + ':'
                    elif checknishosts(host) or checkdns(host):
                        securityline += host + ':'
                    else:
                        sys.stderr.write("#ERROR: removed host/netgroup %s from security!\n" % host)
                if regexnohosts.match(securityline):
                    securityline = securityline[:-1]
                securityline = re.sub(r':$', '', securityline)
        else:
            securityline += values[0]
            if len(values) > 1 and values[1]:
                securityline += '=' + values[1]
        securityline += ','
    securityline = re.sub(r',$', '', securityline)
    return securityline


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


def updatesecurity(securityold, securitynew):
    for host in securitynew:
        if host in securityold:
            for security in securitynew[host]:
                if security not in securityold[host]:
                    securityold[host].append(security)
        else:
            securityold[host] = securitynew[host]
    return securityold
