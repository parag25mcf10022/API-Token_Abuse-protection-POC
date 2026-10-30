#!/usr/bin/env python3
"""
AAP org management client — uses an organization's MASTER KEY.

The master key is for management only (it can't send messages). The server
accepts it only from one of the org admin's APPROVED devices while that admin
is logged in to the web app. This client reuses the same device token as
client.py, so approve this machine on your dashboard first.

Usage:
    AAP_MASTER_KEY=mk_... python3 org_client.py overview
    python3 org_client.py alerts
    python3 org_client.py add-member alice@example.com
    python3 org_client.py set-policy 7 --scopes general,math,coding \\
        --limit requestsPerDay=200 --limit burstPerMinute=20 --cat coding=50
    python3 org_client.py set-policy 7 --all-scopes          # remove scope restriction
    python3 org_client.py org-policy --field policy --limit requestsPerDay=5000
    python3 org_client.py enable 7 | disable 7 | revoke 7
    python3 org_client.py approve-regen 7     # let a locked member generate a new key
    python3 org_client.py unlock 7            # false alarm: restore a disabled key
    python3 org_client.py protection rotate   # org-wide: alert | disable | rotate
    python3 org_client.py resolve <alert-id>

The master key is read from AAP_MASTER_KEY or a hidden prompt — never pass it
on the command line (visible in ps and shell history).
"""

import argparse
import getpass
import json
import os
import sys

try:
    import requests
except ImportError:
    sys.exit("This client needs the 'requests' library:  pip install requests")

from client import device_code, load_device_token, safe

LIMIT_FIELDS = ["burstPerMinute", "requestsPerDay", "requestsPerMonth", "tokensPerDay", "tokensPerMonth"]


def build_policy(args):
    """Turn --scopes/--all-scopes/--limit/--cat flags into a policy object."""
    policy = {"scopes": None, "limits": {"categoryRequestsPerDay": {}}}
    if args.scopes and not args.all_scopes:
        policy["scopes"] = [s.strip() for s in args.scopes.split(",") if s.strip()]
    for item in args.limit or []:
        name, _, value = item.partition("=")
        if name not in LIMIT_FIELDS or not value.isdigit():
            sys.exit(f"Bad --limit {item!r}. Use NAME=INT with NAME in {', '.join(LIMIT_FIELDS)}.")
        policy["limits"][name] = int(value)
    for item in args.cat or []:
        name, _, value = item.partition("=")
        if not value.isdigit():
            sys.exit(f"Bad --cat {item!r}. Use CATEGORY=INT.")
        policy["limits"]["categoryRequestsPerDay"][name] = int(value)
    return policy


def main():
    ap = argparse.ArgumentParser(description="AAP org management (master key)")
    ap.add_argument("--base", default="http://localhost:3000", help="server base URL")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("overview", help="org, members, policies, usage")
    sub.add_parser("alerts", help="open security alerts")
    p = sub.add_parser("resolve", help="resolve an alert")
    p.add_argument("alert_id")
    p = sub.add_parser("add-member", help="create a member (prompts for initial password)")
    p.add_argument("email")
    for name in ("enable", "disable", "revoke", "approve-regen", "unlock"):
        p = sub.add_parser(name, help=f"{name} a member's key")
        p.add_argument("user_id", type=int)
    p = sub.add_parser("protection", help="org-wide action when a key looks compromised")
    p.add_argument("action", choices=["alert", "disable", "rotate"])
    for name, helptext in (("set-policy", "set a member's policy"), ("org-policy", "set org pool / member defaults")):
        p = sub.add_parser(name, help=helptext)
        if name == "set-policy":
            p.add_argument("user_id", type=int)
        else:
            p.add_argument("--field", choices=["policy", "memberDefaults"], default="policy")
        p.add_argument("--scopes", help="comma-separated categories")
        p.add_argument("--all-scopes", action="store_true", help="no scope restriction")
        p.add_argument("--limit", action="append", help="NAME=INT (repeatable)")
        p.add_argument("--cat", action="append", help="CATEGORY=INT requests/day (repeatable)")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    master_key = os.environ.get("AAP_MASTER_KEY") or getpass.getpass("Org master key (input hidden): ")
    token = load_device_token()
    headers = {"X-AAP-Master-Key": master_key.strip(), "X-AAP-Device": token}

    def call(method, path, body=None):
        try:
            r = requests.request(method, f"{base}/api/org{path}", headers=headers, json=body, timeout=10)
        except requests.RequestException as e:
            sys.exit(f"! Could not reach {base}: {safe(e)}")
        try:
            data = r.json()
        except ValueError:
            data = {"error": r.text}
        if r.status_code != 200:
            hint = ""
            if r.status_code == 403 and "device" in str(data.get("error", "")):
                hint = f"\n  (approve this device — code {device_code(token)} — on your dashboard)"
            sys.exit(f"{r.status_code}: {safe(data.get('error', data))}{hint}")
        return data

    if args.cmd == "overview":
        d = call("GET", "/overview")
        for o in d["orgs"]:
            print(f"Org #{o['id']} {safe(o['name'])}  master key {safe(o['masterKeyPrefix'])}…")
            print(f"  pool policy:     {safe(json.dumps(o['policy']))}")
            print(f"  member defaults: {safe(json.dumps(o['memberDefaults']))}")
            print(f"  usage today: {o['usage']['today']['requests']} req / {o['usage']['today']['tokens']} tok")
        print("\nMembers:")
        for u in d["users"]:
            key = ("LOCKED" if u.get("keyLock") else
                   "revoked" if u["keyRevoked"] else ("enabled" if u["keyEnabled"] else "disabled"))
            print(f"  #{u['id']:<4} {safe(u['email']):<28} {safe(u['orgRole'] or ''):<7} key {key:<8} "
                  f"today {u['usage']['today']['requests']} req / {u['usage']['today']['tokens']} tok")
            print(f"        scopes {safe(u['policy'].get('scopes') or 'all')}  limits {safe(json.dumps(u['policy'].get('limits', {})))}")
    elif args.cmd == "alerts":
        alerts = call("GET", "/alerts")["alerts"]
        if not alerts:
            print("No open alerts.")
        for a in alerts:
            print(f"{safe(a['publicId'])}  {safe(a['lastAt'])}  user #{a['userId']} {safe(a['email'])}  "
                  f"{safe(a['type'])}: {safe(a['detail'])}" + (f"  (IP {safe(a['ip'])})" if a.get("ip") else ""))
    elif args.cmd == "resolve":
        call("POST", f"/alerts/{args.alert_id}/resolve")
        print("Resolved.")
    elif args.cmd == "add-member":
        org_id = call("GET", "/overview")["actor"]["orgId"]
        password = getpass.getpass("Temporary password for the member (hidden; they must change it): ")
        d = call("POST", f"/orgs/{org_id}/members", {"email": args.email, "password": password})
        print(f"Created member #{d['id']} {safe(d['email'])}. They log in, set their own password, "
              "then generate their own key.")
    elif args.cmd in ("enable", "disable"):
        d = call("POST", f"/users/{args.user_id}/key-enabled", {"enabled": args.cmd == "enable"})
        print(f"User #{d['userId']} key enabled: {d['keyEnabled']}")
    elif args.cmd == "revoke":
        d = call("POST", f"/users/{args.user_id}/revoke-key")
        print(f"Key revoked; {d['sessionsEnded']} session(s) ended. The user must generate a new key.")
    elif args.cmd == "approve-regen":
        call("POST", f"/users/{args.user_id}/approve-regeneration")
        print(f"User #{args.user_id} may now generate a new key (with their password).")
    elif args.cmd == "unlock":
        call("POST", f"/users/{args.user_id}/unlock")
        print(f"User #{args.user_id} key unlocked.")
    elif args.cmd == "protection":
        org_id = call("GET", "/overview")["actor"]["orgId"]
        d = call("POST", f"/orgs/{org_id}/protection", {"action": args.action})
        print(f"On compromise, the org will now: {d['action']}")
    elif args.cmd == "set-policy":
        d = call("POST", f"/users/{args.user_id}/policy", {"policy": build_policy(args)})
        print(f"Policy for user #{d['userId']}: {safe(json.dumps(d['policy']))}")
    elif args.cmd == "org-policy":
        org_id = call("GET", "/overview")["actor"]["orgId"]
        d = call("POST", f"/orgs/{org_id}/policy", {"field": args.field, "policy": build_policy(args)})
        print(f"Org {d['field']}: {safe(json.dumps(d['policy']))}")


if __name__ == "__main__":
    main()
