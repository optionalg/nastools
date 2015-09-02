# cdotmigration
some scripts that help migrating a 7-Mode NetApp to C-Dot

## genexportpolicy.py

The genexportpolicy.py script transforms a NFS export file (/etc/exports) into NetApp C-Dot export-policys.

simple rules:

* policyname = vol + '_' + qtree
* permissions will get aggregated
* missing (volume) permissions will be added as 0.0.0.0/0
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
    export-policy rule create -vserver vserver1 -policyname vol1 -clientmatch 192.168.1.1 -protocol nfs -rorule any -rwrule never -superuser any
    export-policy rule create -vserver vserver1 -policyname vol1 -clientmatch 0.0.0.0/0 -protocol nfs -rorule any -rwrule never -superuser any -ruleindex 9999
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

