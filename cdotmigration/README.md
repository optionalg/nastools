# cdotmigration
some scripts that help migrating a 7-Mode NetApp to C-Dot


## checkexporthosts.py

The checkexporthosts.py script checks a NFS export file (/etc/exports) for non existant Hosts and Netgroups (NIS).

simple rules:

* outputs wrong hosts/netgroups including exports
* errors will log to stderr
* errors will start with # to prevent accidential execution

### sample

samples/exports_wrong_nisgroup:

    # /etc/exports file
    /vol/vol1               -sec=sys,ro=wrong_nisgroup,root=wrong_nisgroup
    /vol/vol1/qtree1        -sec=sys,ro=192.168.1.1:192.168.1.2,rw=192.168.1.1:192.168.1.2,root=192.168.1.1:192.168.1.2
    /vol/vol1/qtree1/folder -sec=sys,ro=wrong_nisgroup,rw=wrong_nisgroup,root=wrong_nisgroup

run script:

    # run script for imaginary export file samples/exports
    ./checkexporthosts.py samples/exports_wrong_nisgroup

output:

    wrong_nisgroup ['/vol/vol1', '/vol/vol1/qtree1/folder']

### usage
    ./checkexporthosts.py EXPORTFILE

### TODOs
* missing unittests


## cleanupexports.py

The cleanupexports.py script sanitizes a NFS export file (/etc/exports) for later usage with genexportpolicy.py.

simple rules:

* remove non valid (syntax,missing) ips,networks,hosts,netgroups
* @ will be added in front of netgroups
* errors start with # to prevents accidential execution

### sample

samples/wrong_exports:

    


## genexportpolicy.py

The genexportpolicy.py script transforms a NFS export file (/etc/exports) into NetApp C-Dot export-policys.

simple rules:

* policyname = vol + '_' + qtree
* permissions will get aggregated
* missing volume permissions will be added
* permissions without hosts limitation will be transfered to network 0.0.0.0/0
* errors will log to stderr
* errors start with # to prevent accidential execution

### sample

samples/exports:
    
    # /etc/exports file
    /vol/vol1               -sec=sys,ro=192.168.1.1,root=192.168.1.1
    /vol/vol1/qtree1        -sec=sys,ro=192.168.1.1:192.168.1.2,rw=192.168.1.1:192.168.1.2,root=192.168.1.1:192.168.1.2
    /vol/vol1/qtree1/folder -sec=sys,ro=192.168.1.3,rw=192.168.1.3,root=192.168.1.3

run script:

    # run script for imaginary vserver vserver1
    ./genexportpolicy.py samples/exports vserver1

output:

    # script output
    export-policy create -vserver vserver1 -policyname vol1
    export-policy rule create -vserver vserver1 -policyname vol1 -clientmatch 192.168.1.1 -protocol nfs -rorule any -rwrule never -superuser any -ruleindex 500
    export-policy rule create -vserver vserver1 -policyname vol1 -clientmatch 192.168.1.2 -protocol nfs -rorule any -rwrule never -superuser none -ruleindex 500
    export-policy rule create -vserver vserver1 -policyname vol1 -clientmatch 192.168.1.3 -protocol nfs -rorule any -rwrule never -superuser none -ruleindex 500
    export-policy create -vserver vserver1 -policyname vol1_qtree1
    export-policy rule create -vserver vserver1 -policyname vol1_qtree1 -clientmatch 192.168.1.1 -protocol nfs -rorule any -rwrule any -superuser any
    export-policy rule create -vserver vserver1 -policyname vol1_qtree1 -clientmatch 192.168.1.2 -protocol nfs -rorule any -rwrule any -superuser any
    export-policy rule create -vserver vserver1 -policyname vol1_qtree1 -clientmatch 192.168.1.3 -protocol nfs -rorule any -rwrule any -superuser any
    volume modify -vserver vserver1 -volume vol1 -policy vol1
    qtree modify -vserver vserver1 -volume vol1 -qtree qtree1 -export-policy vol1_qtree1

### usage
    ./genexportpolicy.py EXPORTFILE VSERVERNAME

### TODOs
* probably missing ro rule for / (test / implement)
* missing unittests
