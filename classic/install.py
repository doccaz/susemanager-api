#!/usr/bin/python3
import os

# Define the directory
output_dir = "suma_api_tools_py3"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

print(f"[*] Generating SUSE Manager API Tools in '{output_dir}/'...")

# Dictionary of filename -> content
files = {
    "check_activationkey_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass, sys
def parse_args():
    p = argparse.ArgumentParser(description="Check Activation Key")
    p.add_argument('-s', '--server', '--url', dest='url', required=True, help="API URL")
    p.add_argument('-u', '--user', dest='username', required=True, help="Username")
    p.add_argument('-p', '--password', dest='password', required=False, help="Password")
    p.add_argument('-k', '--key', dest='key', required=True, help="Activation Key")
    p.add_argument('--no-verify', dest='no_verify', action='store_true', help="Ignore SSL errors")
    return p.parse_args()
def main():
    args = parse_args()
    pwd = args.password or getpass.getpass(f"Password for {args.username}: ")
    ctx = ssl.create_default_context()
    if args.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        client = xmlrpc.client.ServerProxy(args.url, context=ctx)
        key = client.auth.login(args.username, pwd)
        d = client.activationkey.getDetails(key, args.key)
        print(f"Key: {d.get('key')}\nLimit: {d.get('usage_limit')}\nBase: {d.get('base_channel_label')}")
        print(f"Child Channels: {[c.get('label') for c in d.get('child_channels', [])]}")
        client.auth.logout(key)
    except Exception as e: print(f"Error: {e}")
if __name__=="__main__": main()
''',

    "list_systems_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Systems"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        print(f"{'ID':<10} | {'Hostname':<40} | {'Last Checkin'}")
        for s in c.system.listSystems(k): print(f"{s['id']:<10} | {s['name']:<40} | {s['last_checkin']}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "system_details_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="System Details"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        n = c.system.getName(k, a.sid); devs = c.system.getNetworkDevices(k, a.sid)
        print(f"ID: {a.sid}\nName: {n.get('name')}")
        for d in devs: print(f"Interface: {d.get('interface')} | IP: {d.get('ip')} | MAC: {d.get('hardware_address')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "create_user_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Create User")
    p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password')
    p.add_argument('--new-user',required=True); p.add_argument('--new-pass',required=True); p.add_argument('--email',required=True)
    p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        if c.user.create(k, a.new_user, a.new_pass, "", "New", "User", a.email) == 1: print("User created.")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_users_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Users"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        print(f"{'User':<20} | {'Email'}"); 
        for u in c.user.listUsers(k): print(f"{u['login']:<20} | {u['email']}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_groups_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Groups"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for g in c.systemgroup.listAllGroups(k): print(f"{g.get('id'):<5} | {g.get('name')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "create_group_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Create Group"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--name',required=True); p.add_argument('--desc',default=""); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        c.systemgroup.create(k, a.name, a.desc); print("Group created.")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "add_to_group_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Add System to Group"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('--group',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        c.systemgroup.addOrRemoveSystems(k, a.group, [a.sid], True); print("System added to group.")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "delete_user_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Delete User"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--target-user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        c.user.delete(k, a.target_user); print("User deleted.")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "delete_system_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Delete System"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        c.system.deleteSystem(k, a.sid); print("System deleted.")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "schedule_highstate_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
from datetime import datetime
def main():
    p = argparse.ArgumentParser(description="Schedule Highstate"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        aid = c.system.scheduleApplyHighstate(k, a.sid, datetime.now(), False)
        print(f"Highstate scheduled. Action ID: {aid}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "apply_state_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
from datetime import datetime
def main():
    p = argparse.ArgumentParser(description="Apply Salt State"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('--sls',required=True); p.add_argument('-p','--password'); p.add_argument('--test',action='store_true'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        aid = c.system.scheduleApplySaltStates(k, a.sid, [a.sls], datetime.now(), a.test)
        print(f"State scheduled. Action ID: {aid}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "rebootsystem_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
from datetime import datetime
def main():
    p = argparse.ArgumentParser(description="Reboot System"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        aid = c.system.scheduleReboot(k, a.sid, datetime.now())
        print(f"Reboot scheduled. Action ID: {aid}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_activationkeys_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Activation Keys"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for x in c.activationkey.listActivationKeys(k): print(f"{x.get('key'):<30} | {x.get('base_channel_label')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "create_activationkey_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Create Activation Key"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--key-label',required=True); p.add_argument('--base-channel',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        r = c.activationkey.create(k, a.key_label, "", a.base_channel, 0, [])
        print(f"Key created: {r}"); c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_channels_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Channels"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for x in c.channel.listAllChannels(k): print(f"{x.get('label'):<40} | {x.get('name')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_inactive_systems_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Inactive Systems"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--days',type=int,default=30); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for s in c.system.listInactiveSystems(k, a.days): print(f"{s.get('id'):<10} | {s.get('name')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_activesystems_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
from datetime import datetime, timedelta
def main():
    p = argparse.ArgumentParser(description="List Active Systems"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--days',type=int,default=1); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for s in c.system.listSystems(k): print(f"{s['id']:<10} | {s['name']} | {s['last_checkin']}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_orgs_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Orgs"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for o in c.org.listOrgs(k): print(f"{o.get('id'):<5} | {o.get('name')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_config_channels_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Config Channels"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for cc in c.configuration.listGlobalChannels(k): print(f"{cc.get('label'):<30} | {cc.get('name')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_cvestatus_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List CVE Status"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--cve',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for s in c.audit.listSystemsAffectedByCve(k, a.cve): print(f"{s.get('id'):<10} | {s.get('name')} | {s.get('patch_status')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_locked_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Locked Systems"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for s in c.system.listSystems(k):
             if c.system.getDetails(k, s['id']).get('lock_status'): print(f"{s['id']} | {s['name']} (LOCKED)")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_needsreboot_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Reboot Needed"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for s in c.system.listSystemsWithRebootRequired(k): print(f"{s.get('id'):<10} | {s.get('name')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "list_custominfo_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="List Custom Info"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for v in c.system.getCustomValues(k, a.sid): print(f"{v.get('key_label'):<20} | {v.get('value')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "update_custominfo_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Update Custom Info"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('--key',required=True); p.add_argument('--value',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        c.system.setCustomValues(k, a.sid, {a.key: a.value}); print("Updated.")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "lookup_systemid_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Lookup System ID"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--query',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for s in c.system.search.nameAndDescription(k, a.query): print(f"{s.get('id'):<10} | {s.get('name')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "migrate_system_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Migrate System"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('--target-base',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        aid = c.system.scheduleProductMigration(k, a.sid, a.target_base)
        print(f"Migration scheduled. Action ID: {aid}"); c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "packagesinstalled90days_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Packages > 90 Days"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for x in c.system.listPackages(k, a.sid): print(f"{x.get('name')} | {x.get('install_date')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "get_eventhistory_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Get Event History"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for e in c.system.listSystemEvents(k, a.sid): print(f"{e.get('type'):<20} | {e.get('name')} | {e.get('created')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "get_all_eventhistory_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Get All Event History"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for s in c.system.listSystems(k):
            print(f"--- {s['name']} ---")
            for e in c.system.listSystemEvents(k, s['id'])[:5]: print(f"  {e.get('type')} | {e.get('name')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "get_eventdetails_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Get Event Details"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--aid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        print(c.schedule.getDetails(k, a.aid))
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "runscript_sm_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
from datetime import datetime
def main():
    p = argparse.ArgumentParser(description="Run Remote Script"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('--script',required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        aid = c.system.scheduleScriptRun(k, a.sid, "root", "root", 60, a.script, datetime.now())
        print(f"Script Scheduled. Action ID: {aid}"); c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "getresults_sm_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
def main():
    p = argparse.ArgumentParser(description="Get Script Results"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--aid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        for r in c.system.getScriptResults(k, a.aid): print(f"Return: {r.get('returnCode')}\nOutput:\n{r.get('output')}")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
''',

    "updateallpackages_py3.py": r'''#!/usr/bin/env python3
import argparse, xmlrpc.client, ssl, getpass
from datetime import datetime
def main():
    p = argparse.ArgumentParser(description="Update All Packages"); p.add_argument('-s','--url',required=True); p.add_argument('-u','--user',required=True); p.add_argument('--sid',type=int,required=True); p.add_argument('-p','--password'); p.add_argument('--no-verify',action='store_true')
    a = p.parse_args(); pwd = a.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if a.no_verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    try:
        c = xmlrpc.client.ServerProxy(a.url, context=ctx); k = c.auth.login(a.user, pwd)
        pids = [x['to_package_id'] for x in c.system.listLatestUpgradablePackages(k, a.sid) if 'to_package_id' in x]
        if pids:
            aid = c.system.schedulePackageInstall(k, a.sid, pids, datetime.now())
            print(f"Update scheduled for {len(pids)} packages. Action ID: {aid}")
        else: print("System up to date.")
        c.auth.logout(k)
    except Exception as e: print(e)
if __name__=="__main__": main()
'''
}

for filename, content in files.items():
    filepath = os.path.join(output_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    # Make executable on Unix-like systems
    try:
        os.chmod(filepath, 0o755)
    except:
        pass

print(f"[+] Successfully created {len(files)} files in '{output_dir}/'")
