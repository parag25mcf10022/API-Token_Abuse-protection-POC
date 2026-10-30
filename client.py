#!/usr/bin/env python3
"""
AAP shell client — the "bridge" in Account-Bound API Key Protection.

Before honoring any API call, this client asks the server whether the account
that owns the supplied API key has a *live browser session*. If not, the key
is treated as dead: the user is sent to the web app to log in, and the client
polls until the session goes active.

Usage:
    python3 client.py
    python3 client.py --key ak_xxx          # skip the key prompt
    python3 client.py --base http://localhost:3000

Requires the `requests` library:  pip install requests
"""

import argparse
import sys
import time
import webbrowser

try:
    import requests
except ImportError:
    sys.exit("This client needs the 'requests' library:  pip install requests")


def check_session(base, api_key):
    """Return the server's session-status payload for an api_key, or None on error."""
    try:
        r = requests.get(
            f"{base}/auth/session-status",
            params={"api_key": api_key},
            timeout=5,
        )
        return r.json()
    except requests.RequestException as e:
        print(f"  ! Could not reach the server at {base}: {e}")
        return None


def wait_for_session(base, api_key):
    """Poll session-status until the owning account is logged in. Returns True/False."""
    status = check_session(base, api_key)
    if status is None:
        return False

    if status.get("active"):
        who = status.get("email", "this account")
        print(f"✓ Active session found for {who}.")
        return True

    # Not active — explain why and send the user to log in.
    if status.get("keyEnabled") is False:
        print("✗ This API key has been DISABLED by an admin. Nothing to do.")
        return False

    print("No active session. Please log in at " + base)
    try:
        webbrowser.open(base)
    except Exception:
        pass  # headless / no browser — the printed URL is enough

    print("Waiting for you to log in (Ctrl-C to cancel)", end="", flush=True)
    while True:
        time.sleep(2)
        print(".", end="", flush=True)
        status = check_session(base, api_key)
        if status is None:
            continue
        if status.get("keyEnabled") is False:
            print("\n✗ This API key was disabled by an admin.")
            return False
        if status.get("active"):
            who = status.get("email", "this account")
            print(f"\n✓ Session active for {who}.")
            return True


def send_message(base, api_key, message):
    """POST the message to the protected endpoint and print the result."""
    try:
        r = requests.post(
            f"{base}/api/message",
            json={"api_key": api_key, "message": message},
            timeout=10,
        )
    except requests.RequestException as e:
        print(f"  ! Request failed: {e}")
        return

    data = {}
    try:
        data = r.json()
    except ValueError:
        pass

    if r.status_code == 200:
        print("\n── Response ──────────────────────────────")
        print(data.get("reply", data))
        print(f"  (processed at {data.get('processedAt', 'n/a')})")
    elif r.status_code == 401:
        print(f"\n401 Unauthorized: {data.get('error', 'No active session found')}")
    else:
        print(f"\n{r.status_code}: {data.get('error', r.text)}")


def main():
    ap = argparse.ArgumentParser(description="AAP shell client")
    ap.add_argument("--base", default="http://localhost:3000", help="server base URL")
    ap.add_argument("--key", help="API key (otherwise you'll be prompted)")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    print("=== Account-Bound API Key Protection — shell client ===\n")

    api_key = args.key or input("Enter your API key: ").strip()
    if not api_key:
        sys.exit("No API key provided.")

    # Step 1: verify the browser session before doing anything useful.
    if not wait_for_session(base, api_key):
        sys.exit(1)

    # Step 2: now that the session is live, send messages.
    print("\nSession verified — you can now send messages.")
    print("(blank line or Ctrl-C to quit)\n")
    try:
        while True:
            message = input("message> ").strip()
            if not message:
                break
            send_message(base, api_key, message)
            print()
    except (KeyboardInterrupt, EOFError):
        print()

    print("Done.")


if __name__ == "__main__":
    main()
