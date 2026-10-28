#!/usr/bin/python3
"""
Nagios/Icinga check for Ceph clusters. Runs on the monitoring server using the
ceph client; supply a ceph.conf, keyring and user to access the cluster.

Examples:
  General health:   ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --health
  OSD status:       ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --osd -w 2 -c 3
                    (warn at 2 OSDs down/out, crit at 3)
  MON quorum:       ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --mon -w 1 -c 2
                    (thresholds = MONs missing from quorum, default 1 / 2)
  PG status:        ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --pg
                    (warns if any PG is not active+clean)
  Perf metrics:     ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --perf
  Disk space:       ./check_ceph.py -C ceph.conf --id icinga -k ceph.client.icinga.keyring --df -w 100 -c 50 [--pool rbd] [-b T]
                    (thresholds = MAX AVAIL per pool in the unit given by -b; without --pool every pool is checked)

Supports the pre-Luminous and the Luminous+/Nautilus+ JSON formats.
"""
import sys
import argparse
import json
import subprocess

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
STATE_NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}


def nagios_exit(code, message, perfdata=""):
    out = message
    if perfdata:
        out += "|" + perfdata.strip()
    print(out)
    sys.exit(code)


def ceph(args, *cmd):
    """Run a ceph command and return its parsed JSON output. Any failure -> UNKNOWN."""
    command = ["ceph", "--id", args.id]
    if args.conf:
        command += ["-c", args.conf]
    if args.keyring:
        command += ["-k", args.keyring]
    command += list(cmd) + ["--format", "json"]

    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=args.timeout, check=True)
    except FileNotFoundError:
        nagios_exit(UNKNOWN, "UNKNOWN: ceph binary not found in PATH")
    except subprocess.TimeoutExpired:
        nagios_exit(UNKNOWN, f"UNKNOWN: 'ceph {' '.join(cmd)}' timed out after {args.timeout}s "
                             "(cluster unreachable or no MON quorum?)")
    except subprocess.CalledProcessError as e:
        err = e.stderr.decode(errors="replace").strip().splitlines()
        nagios_exit(UNKNOWN, f"UNKNOWN: 'ceph {' '.join(cmd)}' failed (rc={e.returncode}): "
                             f"{err[-1] if err else 'no error output'}")

    try:
        return json.loads(result.stdout)
    except ValueError:
        nagios_exit(UNKNOWN, f"UNKNOWN: could not parse JSON from 'ceph {' '.join(cmd)}'")


def thresholds(args, default_warn=None, default_crit=None):
    warn = args.warning if args.warning is not None else default_warn
    crit = args.critical if args.critical is not None else default_crit
    if warn is None or crit is None:
        nagios_exit(UNKNOWN, "UNKNOWN: this check needs -w/--warning and -c/--critical")
    try:
        return float(warn), float(crit)
    except ValueError:
        nagios_exit(UNKNOWN, f"UNKNOWN: thresholds must be numbers (got -w {warn} -c {crit})")


def checkHealth(args):
    health = ceph(args, "health")

    # Luminous+: 'status' / 'checks'; older: 'overall_status' / 'summary'
    status = health.get("status") or health.get("overall_status") or "UNKNOWN"

    messages = []
    if "checks" in health:
        severity_order = {"HEALTH_ERR": 0, "HEALTH_WARN": 1}
        checks = sorted(health["checks"].items(),
                        key=lambda kv: severity_order.get(kv[1].get("severity"), 2))
        for name, check in checks:
            msg = f"{name}: {check.get('summary', {}).get('message', '')}"
            if check.get("muted"):
                msg += " [muted]"
            messages.append(msg)
    else:
        messages = [s.get("summary", "") for s in health.get("summary", [])]

    code = {"HEALTH_OK": OK, "HEALTH_WARN": WARNING, "HEALTH_ERR": CRITICAL}.get(status, UNKNOWN)
    text = status if not messages else f"{status}: " + "; ".join(messages)
    nagios_exit(code, text)


def checkOSD(args):
    warn, crit = thresholds(args)
    stat = ceph(args, "osd", "stat")
    stat = stat.get("osdmap", stat)  # Luminous/Mimic nest everything under 'osdmap'

    num, up, inn = stat["num_osds"], stat["num_up_osds"], stat["num_in_osds"]
    missing = max(num - up, num - inn)
    perf = f"num_osds={num} num_up_osds={up} num_in_osds={inn}"
    summary = f"{num} OSDs, {up} up, {inn} in"

    if missing >= crit:
        nagios_exit(CRITICAL, f"CRITICAL: not all OSDs are up and in. {summary}", perf)
    elif missing >= warn:
        nagios_exit(WARNING, f"WARNING: not all OSDs are up and in. {summary}", perf)
    elif missing > 0:
        nagios_exit(OK, f"OK: {missing} OSD(s) down/out, below warning threshold. {summary}", perf)
    else:
        nagios_exit(OK, f"OK: all OSDs are up and in. {summary}", perf)


def checkMON(args):
    warn, crit = thresholds(args, default_warn=1, default_crit=2)
    quorum = ceph(args, "quorum_status")

    all_mons = [m["name"] for m in quorum["monmap"]["mons"]]
    in_quorum = quorum.get("quorum_names", [])
    missing = sorted(set(all_mons) - set(in_quorum))
    perf = f"num_mons={len(all_mons)} mons_in_quorum={len(in_quorum)}"
    summary = (f"{len(in_quorum)}/{len(all_mons)} MONs in quorum, "
               f"leader {quorum.get('quorum_leader_name', '?')}")
    if missing:
        summary += f", missing: {', '.join(missing)}"

    if len(missing) >= crit:
        nagios_exit(CRITICAL, f"CRITICAL: {summary}", perf)
    elif len(missing) >= warn:
        nagios_exit(WARNING, f"WARNING: {summary}", perf)
    else:
        nagios_exit(OK, f"OK: {summary}", perf)


def _pg_is_clean(state_name):
    flags = set(state_name.split("+"))
    return {"active", "clean"} <= flags and "inconsistent" not in flags


def checkPG(args):
    stat = ceph(args, "pg", "stat")
    summary = stat.get("pg_summary", stat)  # Nautilus+ nests under 'pg_summary'

    num_pgs = summary.get("num_pgs", 0)
    states = summary.get("num_pg_by_state", [])
    if num_pgs == 0 or not states:
        nagios_exit(UNKNOWN, "UNKNOWN: no PG statistics available yet (mgr just restarted?)")

    clean = sum(s["num"] for s in states if _pg_is_clean(s["name"]))
    not_clean = [f"{s['num']} {s['name']}" for s in states if not _pg_is_clean(s["name"])]
    perf = f"num_pgs={num_pgs} " + " ".join(f"'{s['name']}'={s['num']}" for s in states)

    if clean < num_pgs:
        nagios_exit(WARNING, f"WARNING: {num_pgs - clean} of {num_pgs} PGs not active+clean: "
                             + ", ".join(not_clean), perf)
    else:
        nagios_exit(OK, f"OK: all {num_pgs} PGs are active+clean", perf)


def checkPerf(args):
    # 'ceph status' -> pgmap carries the client IO rates in all versions since Luminous.
    # Keys are omitted while the value is 0.
    status = ceph(args, "status")
    pgmap = status.get("pgmap", {})
    rb = pgmap.get("read_bytes_sec", 0)
    wb = pgmap.get("write_bytes_sec", 0)
    rop = pgmap.get("read_op_per_sec", 0)
    wop = pgmap.get("write_op_per_sec", 0)
    io = pgmap.get("io_sec", rop + wop)

    perf = (f"read_bytes_sec={rb} write_bytes_sec={wb} read_op_per_sec={rop} "
            f"write_op_per_sec={wop} io_sec={io}")
    nagios_exit(OK, f"OK: client IO {rb / 1024**2:.1f} MiB/s rd, {wb / 1024**2:.1f} MiB/s wr, "
                    f"{rop} op/s rd, {wop} op/s wr", perf)


def checkDF(args):
    warn, crit = thresholds(args)
    if crit > warn:
        nagios_exit(UNKNOWN, "UNKNOWN: for --df the thresholds are free space, so -c must be <= -w")

    units = {"G": ("GB", 1024**3), "T": ("TB", 1024**4), "P": ("PB", 1024**5)}
    unit_key = (args.byte or "T").upper()
    if unit_key not in units:
        nagios_exit(UNKNOWN, f"UNKNOWN: invalid -b/--byte '{args.byte}', use G, T or P")
    unit, div = units[unit_key]

    df = ceph(args, "df")
    st = df["stats"]
    pools = {}
    for p in df["pools"]:
        s = p["stats"]
        pools[p["name"]] = {
            "bytes_used": s.get("bytes_used", s.get("kb_used", 0) * 1024),
            "max_avail": s["max_avail"],
            "objects": s.get("objects", 0),
        }

    # Perfdata in plain bytes (UOM 'B'), graphers scale this themselves
    perf = [f"global_total_bytes={st['total_bytes']}B",
            f"global_used_bytes={st['total_used_bytes']}B",
            f"global_avail_bytes={st['total_avail_bytes']}B"]
    for name, p in pools.items():
        perf += [f"'{name}_bytes_used'={p['bytes_used']}B",
                 f"'{name}_max_avail'={p['max_avail']}B;{int(warn * div)};{int(crit * div)};0",
                 f"'{name}_objects'={p['objects']}"]
    perf = " ".join(perf)

    def fmt(b):
        return f"{b / div:.2f}{unit}"

    if args.pool:
        if args.pool not in pools:
            nagios_exit(UNKNOWN, f"UNKNOWN: pool '{args.pool}' not found "
                                 f"(available: {', '.join(sorted(pools))})", perf)
        avail = pools[args.pool]["max_avail"] / div
        text = f"Ceph pool {args.pool} has {fmt(pools[args.pool]['max_avail'])} available"
        if avail < crit:
            nagios_exit(CRITICAL, f"CRITICAL: {text}", perf)
        elif avail < warn:
            nagios_exit(WARNING, f"WARNING: {text}", perf)
        else:
            nagios_exit(OK, f"OK: {text}", perf)

    crit_list, warn_list = [], []
    for name, p in sorted(pools.items()):
        avail = p["max_avail"] / div
        if avail < crit:
            crit_list.append(f"{name}:{fmt(p['max_avail'])}")
        elif avail < warn:
            warn_list.append(f"{name}:{fmt(p['max_avail'])}")

    if crit_list:
        nagios_exit(CRITICAL, f"CRITICAL: Ceph pool(s) critically low on free space. "
                              f"Critical: {', '.join(crit_list)}"
                              + (f" Warning: {', '.join(warn_list)}" if warn_list else ""), perf)
    elif warn_list:
        nagios_exit(WARNING, f"WARNING: Ceph pool(s) low on free space: {', '.join(warn_list)}", perf)
    else:
        nagios_exit(OK, f"OK: all {len(pools)} Ceph pools are within free space thresholds, "
                        f"{fmt(st['total_avail_bytes'])} raw free", perf)


def main():
    parser = argparse.ArgumentParser(description='Runs health checks against a ceph cluster. This is designed to run on the monitoring server using the ceph client software. Supply a ceph.conf, keyring, and user to access the cluster.')
    parser.add_argument('-C', '--conf', help='ceph.conf file, defaults to /etc/ceph/ceph.conf.')
    parser.add_argument('-id', '--id', help='Ceph authx user', required=True)
    parser.add_argument('-k', '--keyring', help='Path to ceph keyring if not in /etc/ceph/client.$id.keyring')
    parser.add_argument('--health', help='Get general health status. ex. HEALTH_OK, HEALTH_WARN', action="store_true")
    parser.add_argument('-o', '--osd', help='OSD status. Thresholds are in number of OSDs down or out', action="store_true")
    parser.add_argument('-m', '--mon', help='MON quorum. Thresholds are in number of MONs missing from quorum (default -w 1 -c 2)', action="store_true")
    parser.add_argument('-p', '--pg', help='PG status. No thresholds due to the large number of pg states.', action="store_true")
    parser.add_argument('--perf', help='collects additional ceph performance statistics', action='store_true')
    parser.add_argument('--df', help='Disk/cluster usage. Reports global and all pools unless --pool is used. Warning and critical are amounts (in -b units) free to the pools. This is not Raw Free, but Max Avail to the pools based on rep or k,m settings. If you do not define a pool the threshold is run against all the pools in the cluster.', action="store_true")
    parser.add_argument('-b', '--byte', help="Unit for DF data and thresholds: G, T or P. Use with --df. Defaults to T")
    parser.add_argument('--pool', help='Pool. Use with --df')
    parser.add_argument('--objects', help='Object counts based on pool (not implemented)')
    parser.add_argument('-w', '--warning', help='Warning threshold. See specific checks for value types')
    parser.add_argument('-c', '--critical', help='Critical threshold. See specific checks for value types')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='Timeout for ceph commands in seconds (default 30)')

    args = parser.parse_args()

    if args.health:
        checkHealth(args)
    elif args.osd:
        checkOSD(args)
    elif args.mon:
        checkMON(args)
    elif args.pg:
        checkPG(args)
    elif args.df:
        checkDF(args)
    elif args.perf:
        checkPerf(args)
    else:
        parser.print_usage()
        nagios_exit(UNKNOWN, "UNKNOWN: no check selected (--health, --osd, --mon, --pg, --perf or --df)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # never hand Nagios a traceback (exit 1 = WARNING)
        nagios_exit(UNKNOWN, f"UNKNOWN: unexpected error {type(e).__name__}: {e}")
