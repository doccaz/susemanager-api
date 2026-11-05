#!/usr/bin/env python3
"""
SUSE Multi-Linux Manager / Uyuni API - Vulnerability Report per System Group

Crosses system groups with patch severity: for each group, shows how many
applicable security patches exist by severity (Critical / Important /
Moderate / Low), how many systems have at least one critical patch pending,
plus bugfix/enhancement counts and the average System Currency score.

Data source: system.getSystemCurrencyScores (same data as the System Currency
report), joined with systemgroup.listSystemsMinimal.

Note: patch counts are per system (system x patch). If 10 systems in a group
each miss the same critical patch, the group shows 10 critical.
"""
import argparse, xmlrpc.client, ssl, getpass, sys, csv

SEV = [('crit', 'Critical'), ('imp', 'Important'), ('mod', 'Moderate'), ('low', 'Low')]
OTHER = [('bug', 'Bugfix'), ('enh', 'Enhancement')]
UNGROUPED = '(no group)'


def summarize(name, members, scores):
    row = {'group': name, 'systems': len(members), 'with_critical': 0}
    for k, _ in SEV + OTHER:
        row[k] = 0
    total_score = 0
    for sid in members:
        s = scores.get(sid, {})
        for k, _ in SEV + OTHER:
            row[k] += int(s.get(k, 0) or 0)
        if int(s.get('crit', 0) or 0) > 0:
            row['with_critical'] += 1
        total_score += int(s.get('score', 0) or 0)
    row['avg_score'] = round(total_score / len(members), 1) if members else 0
    return row


def main():
    p = argparse.ArgumentParser(description="Vulnerability (patch severity) report per system group")
    p.add_argument('-s', '--server'); p.add_argument('--url'); p.add_argument('-u', '--user', required=True)
    p.add_argument('-p', '--password'); p.add_argument('--verify', action='store_true')
    p.add_argument('-g', '--group', action='append',
                   help="Only report this group (can be repeated). Default: all groups")
    p.add_argument('--ungrouped', action='store_true', help="Also report systems that belong to no group")
    p.add_argument('--summary-only', action='store_true',
                   help="Only print the per-group summary, not the systems of each affected group")
    p.add_argument('--only-critical', action='store_true',
                   help="In the per-system listing/CSV, list only systems with critical patches pending")
    p.add_argument('--csv', metavar='FILE', help="Write the per-system breakdown to a CSV file")
    args = p.parse_args()

    if args.url: api_url = args.url
    elif args.server: api_url = f"https://{args.server}/rpc/api"
    else: print("[!] Error: Provide -s/--server or --url"); sys.exit(1)

    pwd = args.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if not args.verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

    try:
        c = xmlrpc.client.ServerProxy(api_url, context=ctx); k = c.auth.login(args.user, pwd)

        print("[*] Fetching system currency scores...")
        scores = {s['sid']: s for s in c.system.getSystemCurrencyScores(k)}
        names = {s['id']: s['name'] for s in c.system.listSystems(k)}

        groups = c.systemgroup.listAllGroups(k)
        if args.group:
            wanted = set(args.group)
            missing = wanted - {g['name'] for g in groups}
            for m in sorted(missing): print(f"[!] Group not found: {m}")
            groups = [g for g in groups if g['name'] in wanted]

        print(f"[*] Reading members of {len(groups)} group(s)...")
        membership = {}
        for g in groups:
            membership[g['name']] = [s['id'] for s in c.systemgroup.listSystemsMinimal(k, g['name'])]

        if args.ungrouped:
            grouped = set()
            for g in c.systemgroup.listAllGroups(k):
                grouped.update(s['id'] for s in c.systemgroup.listSystemsMinimal(k, g['name']))
            membership[UNGROUPED] = [sid for sid in names if sid not in grouped]

        c.auth.logout(k)
    except Exception as e:
        print(f"[!] Error: {e}"); sys.exit(1)

    rows = [summarize(n, m, scores) for n, m in membership.items()]
    rows.sort(key=lambda r: (r['crit'], r['imp'], r['mod'], r['low']), reverse=True)

    hdr = (f"{'Group':<30} | {'Systems':>7} | {'w/Crit':>6} | {'Critical':>8} | {'Important':>9} | "
           f"{'Moderate':>8} | {'Low':>6} | {'Bugfix':>6} | {'Enh':>5} | {'AvgScore':>8}")
    print("\nPending security patches per group (system x patch counts):\n")
    print(hdr); print('-' * len(hdr))
    for r in rows:
        print(f"{r['group'][:30]:<30} | {r['systems']:>7} | {r['with_critical']:>6} | {r['crit']:>8} | "
              f"{r['imp']:>9} | {r['mod']:>8} | {r['low']:>6} | {r['bug']:>6} | {r['enh']:>5} | "
              f"{r['avg_score']:>8}")
    print("\nw/Crit = systems with at least one critical patch pending. "
          "Systems in several groups are counted in each.")

    def system_rows():
        for gname, members in membership.items():
            for sid in members:
                s = scores.get(sid, {})
                if args.only_critical and not int(s.get('crit', 0) or 0):
                    continue
                yield gname, sid, s

    def affected(s):
        return any(int(s.get(k, 0) or 0) for k, _ in SEV)

    if not args.summary_only:
        print("\nAffected systems per group:")
        for gname in [r['group'] for r in rows]:
            sel = [(sid, s) for g, sid, s in system_rows() if g == gname and affected(s)]
            if not sel:
                print(f"\n== {gname}: no affected systems =="); continue
            print(f"\n== {gname} ({len(sel)} affected of {len(membership[gname])} system(s)) ==")
            sel.sort(key=lambda x: (int(x[1].get('crit', 0) or 0), int(x[1].get('imp', 0) or 0)), reverse=True)
            print(f"  {'ID':<12} | {'Name':<35} | {'Crit':>5} | {'Imp':>5} | {'Mod':>5} | {'Low':>5} | {'Score':>6}")
            for sid, s in sel:
                print(f"  {sid:<12} | {names.get(sid, '?')[:35]:<35} | {s.get('crit', 0):>5} | {s.get('imp', 0):>5} | "
                      f"{s.get('mod', 0):>5} | {s.get('low', 0):>5} | {s.get('score', 0):>6}")

    if args.csv:
        with open(args.csv, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['group', 'system_id', 'system_name'] + [l for _, l in SEV + OTHER] + ['score'])
            for gname, sid, s in system_rows():
                w.writerow([gname, sid, names.get(sid, '')] + [s.get(k, 0) for k, _ in SEV + OTHER] + [s.get('score', 0)])
        print(f"\n[*] Per-system breakdown written to {args.csv}")


if __name__ == "__main__": main()
