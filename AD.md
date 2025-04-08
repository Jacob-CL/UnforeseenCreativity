# ldap
We can communicate with the directory service using LDAP queries to ask the service for information. Lightweight Directory Access Protocol (LDAP) is an integral part of Active Directory (AD). AD Powershell module cmdlets with `-Filter` and `-LDAPFilter` flags are usually how search or filter for LDAP information. LDAPFilter uses Polish notation.
- For alisting of all user rights assigned to your current user - `whoami /priv`
- Get all AD groups - `Get-ADObject -LDAPFilter '(objectClass=group)' | select name`
- Get all administratively disabled accounts - `Get-ADObject -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' -Properties * | select samaccountname,useraccountcontrol`
- Find administrative AD groups - `Get-ADGroup -Filter "adminCount -eq 1" | select Name`
- Search all hosts in the domain like SQL* - `Get-ADComputer  -Filter "DNSHostName -like 'SQL*'"` (Be careful filtering on DNSHostname, it's assuming it's correctly labelled.)
- Find computer that starts with RD - `Get-ADComputer -Filter {Name -like 'RD*'} - Properties *`
- Allo domain admin users with DoesNotRequirePreAuth - `Get-ADUser -Filter {adminCount -eq '1' -and DoesNotRequirePreAuth -eq 'True'}`
- All admin users with a ServicePrincipalName (SPN) - `Get-ADUser -Filter "adminCount -eq '1'" -Properties * | where servicePrincipalName -ne $null | select SamAccountName,MemberOf,ServicePrincipalName | fl`
- Filter on Disabled User Accounts - `Get-ADUser -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=2)' | select name`
- This rule will find all groups that the user Harry Jones is a member of - `Get-ADGroup -LDAPFilter '(member:1.2.840.113556.1.4.1941:=CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL)' | select Name`
- Search for all domain users that do not have a blank description field - `Get-ADUser -Properties * -LDAPFilter '(&(objectCategory=user)(description=*))' | select samaccountname,description`
- Find Trusted Computers - `Get-ADComputer -Properties * -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' | select DistinguishedName,servicePrincipalName,TrustedForDelegation | fl`
- Find admin users where the password can be blank - `Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl`
- Find users where password can be blank (no extra filters - `Get-AdUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))(adminCount=1)' -Properties * | select name,memberof | fl`
- Find nested group membership of a user with the RecursiveMatch parameter - `Get-ADGroup -Filter 'member -RecursiveMatch "CN=Harry Jones,OU=Network Ops,OU=IT,OU=Employees,DC=INLANEFREIGHT,DC=LOCAL"' | select name`
- Count all AD users - `(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -Filter *).count`
- Count all AD users within all child containers - `(Get-ADUser -SearchBase "OU=Employees,DC=INLANEFREIGHT,DC=LOCAL" -SearchScope Subtree -Filter *).count`
- What group is a IT Support group nested to? - `Get-ADGroup -Identity "IT Support" -Properties MemberOf | Select-Object -ExpandProperty MemberOf`
- User accounts that require a smart card for interactive logon (SMARTCARD_REQUIRED) - `Get-ADUser -Filter {SmartcardLogonRequired -eq $true} -Properties SmartcardLogonRequired | Select-Object Name, SamAccountName`
- Find user who has useraccountcontrol attribute to 262656 - `Get-ADUser -LDAPFilter "(userAccountControl=262656)" -Properties userAccountControl, DistinguishedName | Select-Object -First 1 Name, SamAccountName, DistinguishedName, userAccountControl`
- Who is a member of a group via nested groups? - ```function Get-NestedGroupMembers {param ([string]$GroupName)
Get-ADGroupMember -Identity $GroupName -Recursive | Select-Object Name, SamAccountName, ObjectClass} Get-NestedGroupMembers -GroupName "IT Support"```
- Show me all admin groups - `Get-ADGroup -LDAPFilter "(adminCount=1)" | Select-Object Name, SamAccountName`
- Count me all admin groups - `(Get-ADGroup -LDAPFilter "(adminCount=1)" | Select-Object Name, SamAccountName).count`
- Find all users subject to ASREPRoasting and NOT a protected user - ```$asrepUsers = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, SamAccountName | Select-Object SamAccountName
$protectedUsers = Get-ADGroupMember -Identity "Protected Users" | Select-Object -ExpandProperty SamAccountName
$asrepUsers | Where-Object { $_.SamAccountName -notin $protectedUsers }```
- Get all users with a SPN set - `Gety-ADObject -LDAPFilter "(servicePrincipalName=*)`



## Unauthenticated LDAP enumeration
To check if we can interact with LDAP without credentials run this python:
```p
from ldap3 import *
s = Server('<IP>', get_info = ALL)
c = Connection(s,'','')
c.bind()

Should return: True

s.info
exit()
```
If you can anonymously enumerate ldap, then `s.info` should give you the CN and DCs e.g `CN=Configuration,DC=sequel,DC=htb`. Then you can use the ldapsearch tool.
- `ldapsearch -H ldap://10.129.1.207 -x -b "dc=inlanefreight,dc=local"`

Windapsearch.py is a Python script used to perform anonymous and authenticated LDAP enumeration of AD users, groups, and computers using LDAP queries. It is an alternative to tools such as ldapsearch, which require you to craft custom LDAP queries:
- To confirm connection anonymously - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" --functionality`
- Pull list of users - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -U`
- Pull list of computers - `python3 windapsearch.py --dc-ip 10.129.1.207 -u "" -C`
- Authenitcated search - `python3 windapsearch.py --dc-ip 10.129.85.28 -u "rose" -p "KxEPkKe6R8su"`

ldapsearch-ad.py is another tool worth trying:
- `python3 ldapsearch-ad.py -h`
- Gives you everything - `python3 ldapsearch-ad.py -l 10.129.85.28 -t info`
- Users that can be ASREPRoasted - `python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t asreproast`

## Authenticated LDAP enumeration
Remeber you may lack RDP perms to the box but still have perms to auth enumerate with LDAP
- `python3 windapsearch.py --dc-ip 10.129.1.207 -u inlanefreight\\james.cross --da` (`domain\\username`)
- `python3 ldapsearch-ad.py -l 10.129.1.207 -d inlanefreight -u james.cross -p Summer2020 -t pass-pols`
- Will reveal if accounts are prone to kerberoast: `python3 ldapsearch-ad.py -l 10.129.85.28 -d sequel -u rose -p KxEPkKe6R8su -t all`
- 

# DSQuery
DS Tools is available by default on all modern Windows operating systems but required domain connectivity to perform enumeration activities.
- `dsquery user "OU=Employees,DC=inlanefreight,DC=local" -name * -scope subtree -limit 0 | dsget user -samid -
pwdneverexpires | findstr /V no`


# WMI
Windows Management Instrumentation (WMI) can also be used to access and query objects in Active Directory. Many scripting languages can interact with the WMI AD provider, but PowerShell makes this very easy.
- `Get-WmiObject -Class win32_group -Filter "Domain='INLANEFREIGHT'" | Select Caption,Name`

# ADSI
Active Directory Service Interfaces (ADSI) is a set of COM interfaces that can query Active Directory. PowerShell again provides an easy way to interact with it.
- `([adsisearcher]"(&(objectClass=Computer))").FindAll() | select Path`

