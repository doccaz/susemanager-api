#!/usr/bin/env python3
"""
SUSE Multi-Linux Manager / Uyuni API - Unique CVEs per System Group, with CVSS

For each system group, lists the UNIQUE CVEs still open on its systems (fixed by
an applicable but not installed security patch), bucketed by CVSS v3 base score:
    Critical 9.0-10.0 | High 7.0-8.9 | Medium 4.0-6.9 | Low 0.1-3.9 | Unknown

SUMA does not store CVSS scores, so they come from SUSE's CVSS score feed, a
single ~7 MB YAML file updated daily:
    https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml
Downloaded on each run (nothing is sent but the HTTP request), or read from a
local copy with --cvss-file for air-gapped servers.

Score used per CVE: the highest CVSS v3.x base score; if SUSE has no v3 score,
v4 is used, then v2 (the CSV says which version each score came from).

API calls: one system.getRelevantErrataByType per grouped system, plus one
errata.listCves per security patch not yet in the local patch->CVE cache
(~/.cache/suma-patch-cves-<server>.json). The first run pays for all patches
(4 parallel calls); later runs only ask about new ones. --no-cache disables it.
"""
import argparse, xmlrpc.client, ssl, getpass, sys, csv, json, os, threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CVSS_URL = "https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml"
BANDS = [('Critical', 9.0), ('High', 7.0), ('Medium', 4.0), ('Low', 0.1)]
BAND_NAMES = [b for b, _ in BANDS] + ['Unknown']
UNGROUPED = '(no group)'


def band(score):
    if score is None: return 'Unknown'
    for name, low in BANDS:
        if score >= low: return name
    return 'Unknown'


def parse_cvss_yaml(text):
    """Parse suse-cvss-scores.yaml into {CVE: [(version, score, vector), ...]}.

    The file has a fixed layout (CVE -> cvss -> list of version/score/vector),
    so a line parser is enough and avoids depending on PyYAML.
    """
    data, cve, entry = {}, None, None
    for line in text.splitlines():
        st = line.strip()
        if not line.startswith(' ') and st.endswith(':') and st.startswith('CVE-'):
            cve = st[:-1]; data[cve] = []
        elif st.startswith('- version:') and cve:
            entry = [st.split(':', 1)[1].strip(), None, '']; data[cve].append(entry)
        elif st.startswith('score:') and entry is not None:
            entry[1] = float(st.split(':', 1)[1])
        elif st.startswith('vector:') and entry is not None:
            entry[2] = st.split(':', 1)[1].strip()
    return data


def pick_score(entries):
    """Highest v3.x score; else v4; else v2. Returns {'score','vector','version'}."""
    for prefix in ('3', '4', '2'):
        cand = [e for e in entries if e[0].split('.')[0] == prefix and e[1] is not None]
        if cand:
            ver, score, vec = max(cand, key=lambda e: e[1])
            return {'score': score, 'vector': vec, 'version': ver}
    return {'score': None, 'vector': '', 'version': ''}


def load_cvss(cvss_file=None):
    if cvss_file:
        print(f"[*] Reading CVSS scores from {cvss_file}...")
        with open(cvss_file) as f: text = f.read()
    else:
        print(f"[*] Downloading CVSS scores from {CVSS_URL}...")
        # ftp.suse.com is always verified, regardless of --verify (which is for SUMA)
        with urllib.request.urlopen(CVSS_URL, timeout=120, context=ssl.create_default_context()) as r:
            text = r.read().decode()
    data = parse_cvss_yaml(text)
    print(f"    {len(data)} CVEs in feed")
    return data


def main():
    p = argparse.ArgumentParser(description="Unique CVEs per system group, bucketed by CVSS score")
    p.add_argument('-s', '--server'); p.add_argument('--url'); p.add_argument('-u', '--user', required=True)
    p.add_argument('-p', '--password'); p.add_argument('--verify', action='store_true')
    p.add_argument('-g', '--group', action='append',
                   help="Only report this group (can be repeated). Default: all groups")
    p.add_argument('--ungrouped', action='store_true', help="Also report systems that belong to no group")
    p.add_argument('--details', action='store_true', help="List the CVEs of each group, highest CVSS first")
    p.add_argument('--min-cvss', type=float, default=0.0,
                   help="In --details/CSV, only show CVEs with CVSS >= this value (e.g. 9.0)")
    p.add_argument('--csv', metavar='FILE', help="Write one row per group x CVE to a CSV file")
    p.add_argument('--no-cache', action='store_true',
                   help="Do not use/update the local patch->CVE cache")
    p.add_argument('--workers', type=int, default=4,
                   help="Parallel errata.listCves calls for uncached patches (default 4)")
    p.add_argument('--cvss-file', metavar='FILE',
                   help="Offline: local copy of suse-cvss-scores.yaml instead of downloading it")
    args = p.parse_args()

    if args.url: api_url = args.url
    elif args.server: api_url = f"https://{args.server}/rpc/api"
    else: print("[!] Error: Provide -s/--server or --url"); sys.exit(1)

    pwd = args.password or getpass.getpass()
    ctx = ssl.create_default_context()
    if not args.verify: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

    try:
        c = xmlrpc.client.ServerProxy(api_url, context=ctx); k = c.auth.login(args.user, pwd)
        names = {s['id']: s['name'] for s in c.system.listSystems(k)}

        all_groups = c.systemgroup.listAllGroups(k)
        groups = all_groups
        if args.group:
            wanted = set(args.group)
            for m in sorted(wanted - {g['name'] for g in all_groups}): print(f"[!] Group not found: {m}")
            groups = [g for g in all_groups if g['name'] in wanted]

        print(f"[*] Reading members of {len(groups)} group(s)...")
        membership = {g['name']: [s['id'] for s in c.systemgroup.listSystemsMinimal(k, g['name'])]
                      for g in groups}
        if args.ungrouped:
            grouped = set()
            for g in all_groups:
                grouped.update(s['id'] for s in c.systemgroup.listSystemsMinimal(k, g['name']))
            membership[UNGROUPED] = [sid for sid in names if sid not in grouped]

        systems = sorted({sid for m in membership.values() for sid in m})
        print(f"[*] Reading pending security patches of {len(systems)} system(s)...")
        sys_adv = {}
        for i, sid in enumerate(systems, 1):
            sys_adv[sid] = {e['advisory_name'] for e in c.system.getRelevantErrataByType(k, sid, 'Security Advisory')}
            if i % 50 == 0: print(f"    {i}/{len(systems)}")

        advisories = sorted(set().union(*sys_adv.values())) if sys_adv else []
        host = args.server or api_url.split('/')[2]
        cache_file = os.path.expanduser(f"~/.cache/suma-patch-cves-{host.replace(':', '_')}.json")
        cache = {}
        if not args.no_cache and os.path.exists(cache_file):
            try:
                with open(cache_file) as f: cache = json.load(f)
            except (OSError, ValueError): cache = {}
        todo = [a for a in advisories if a not in cache]
        print(f"[*] Mapping {len(advisories)} security patch(es) to CVEs "
              f"({len(advisories) - len(todo)} cached, {len(todo)} to fetch)...")

        local = threading.local()
        def list_cves(a):
            # xmlrpc ServerProxy is not thread-safe: one per worker thread, same session key
            if not hasattr(local, 'c'): local.c = xmlrpc.client.ServerProxy(api_url, context=ctx)
            for attempt in (1, 2):
                try:
                    return a, sorted(local.c.errata.listCves(k, a)), None
                except (xmlrpc.client.Fault, xmlrpc.client.ProtocolError, OSError) as e:
                    err = e
            return a, None, err

        failed = []
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            for i, (a, cves, err) in enumerate(ex.map(list_cves, todo), 1):
                if cves is None:
                    print(f"[!] Skipping {a}: {err}"); failed.append(a)
                    if len(failed) >= 10:
                        ex.shutdown(wait=False, cancel_futures=True)
                        raise RuntimeError("10 patches failed in errata.listCves; the server may be overloaded or down")
                else:
                    cache[a] = cves
                if i % 100 == 0: print(f"    {i}/{len(todo)}")
        if failed:
            print(f"[!] {len(failed)} patch(es) could not be mapped to CVEs and are NOT in the report: {', '.join(failed)}")
        if not args.no_cache and todo:
            try:
                os.makedirs(os.path.dirname(cache_file), exist_ok=True)
                with open(cache_file, 'w') as f: json.dump(cache, f)
            except OSError as e:
                print(f"[!] Could not save patch->CVE cache: {e}")
        adv_cves = {a: set(cache[a]) for a in advisories if a in cache}

        c.auth.logout(k)
    except Exception as e:
        print(f"[!] Error: {e}"); sys.exit(1)

    try:
        feed = load_cvss(args.cvss_file)
    except Exception as e:
        print(f"[!] Error loading CVSS scores: {e}"); sys.exit(1)
    all_cves = set().union(*adv_cves.values()) if adv_cves else set()
    cvss = {cve: pick_score(feed.get(cve, [])) for cve in all_cves}
    print(f"    {sum(1 for v in cvss.values() if v['score'] is not None)} of {len(all_cves)} open CVEs have a score")

    # group -> cve -> {'systems': set, 'advisories': set}
    report = {}
    for gname, members in membership.items():
        g = report.setdefault(gname, {})
        for sid in members:
            for a in sys_adv.get(sid, ()):
                for cve in adv_cves.get(a, ()):
                    e = g.setdefault(cve, {'systems': set(), 'advisories': set()})
                    e['systems'].add(sid); e['advisories'].add(a)

    rows = []
    for gname, cves in report.items():
        r = {'group': gname, 'systems': len(membership[gname]), 'cves': len(cves), 'max': None}
        for b in BAND_NAMES: r[b] = 0
        crit_systems = set()
        for cve, e in cves.items():
            s = cvss[cve]['score']
            r[band(s)] += 1
            if s is not None and (r['max'] is None or s > r['max']): r['max'] = s
            if band(s) == 'Critical': crit_systems |= e['systems']
        r['crit_systems'] = len(crit_systems)
        rows.append(r)
    rows.sort(key=lambda r: tuple(r[b] for b in BAND_NAMES), reverse=True)

    hdr = (f"{'Group':<30} | {'Systems':>7} | {'w/Crit':>6} | {'CVEs':>6} | {'Critical':>8} | {'High':>6} | "
           f"{'Medium':>6} | {'Low':>5} | {'Unknown':>7} | {'MaxCVSS':>7}")
    print("\nUnique open CVEs per group, by CVSS base score:\n")
    print(hdr); print('-' * len(hdr))
    for r in rows:
        mx = f"{r['max']:.1f}" if r['max'] is not None else '-'
        print(f"{r['group'][:30]:<30} | {r['systems']:>7} | {r['crit_systems']:>6} | {r['cves']:>6} | "
              f"{r['Critical']:>8} | {r['High']:>6} | {r['Medium']:>6} | {r['Low']:>5} | {r['Unknown']:>7} | {mx:>7}")
    print("\nw/Crit = systems with at least one open CVE scored CVSS >= 9.0. "
          "Unknown = no CVSS published by SUSE.\nSystems in several groups are counted in each.")

    def cve_rows(gname):
        out = []
        for cve, e in report[gname].items():
            s = cvss[cve]['score']
            if args.min_cvss and (s is None or s < args.min_cvss): continue
            out.append((cve, cvss[cve], e))
        out.sort(key=lambda x: (x[1]['score'] if x[1]['score'] is not None else -1, len(x[2]['systems'])), reverse=True)
        return out

    if args.details:
        for gname in [r['group'] for r in rows]:
            sel = cve_rows(gname)
            print(f"\n== {gname} ({len(sel)} CVE(s)) ==")
            if not sel: continue
            print(f"  {'CVE':<17} | {'CVSS':>5} | {'Ver':<4} | {'Band':<8} | {'Systems':>7} | Patches")
            for cve, info, e in sel:
                sc = f"{info['score']:.1f}" if info['score'] is not None else '-'
                advs = ', '.join(sorted(e['advisories']))
                print(f"  {cve:<17} | {sc:>5} | {info['version']:<4} | {band(info['score']):<8} | "
                      f"{len(e['systems']):>7} | {advs[:60]}{'...' if len(advs) > 60 else ''}")

    if args.csv:
        with open(args.csv, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['group', 'cve', 'cvss', 'cvss_version', 'band', 'cvss_vector',
                        'affected_systems', 'affected_system_names', 'patches'])
            for gname in report:
                for cve, info, e in cve_rows(gname):
                    w.writerow([gname, cve, info['score'] if info['score'] is not None else '', info['version'],
                                band(info['score']), info['vector'], len(e['systems']),
                                ';'.join(sorted(names.get(s, str(s)) for s in e['systems'])),
                                ';'.join(sorted(e['advisories']))])
        print(f"\n[*] Group x CVE breakdown written to {args.csv}")


if __name__ == "__main__": main()
