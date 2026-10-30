#!/usr/bin/env python3
"""
AAP shell client — the "bridge" in Account-Bound API Key Protection.

Before honoring any API call, this client asks the server whether the account
that owns the supplied API key has a *live browser session*. If not, the key
is treated as dead: the user is sent to the web app to log in, and the client
polls until the session goes active.

Usage:
    python3 client.py                       # prompts for the key (hidden)
    AAP_API_KEY=ak_xxx python3 client.py    # or read it from the environment
    python3 client.py --base http://localhost:3000

The key is sent only in the X-API-Key header, never in a URL. Avoid passing it
as a command-line argument: argv is visible in `ps` and saved in shell history.

Requires the `requests` library:  pip install requests
"""

import argparse
import getpass
import hashlib
import os
import re
import secrets
import socket
import sys
import time
import webbrowser

try:
    import requests
except ImportError:
    sys.exit("This client needs the 'requests' library:  pip install requests")


# Output encoding for the terminal: server-supplied text (replies echo user
# input) must not be able to inject ANSI/OSC escape sequences that rewrite the
# screen, retitle the window, or plant clickable links. Strip C0/C1 control
# characters (keeping newline and tab) before printing anything from the server.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(value):
    """Render a server-supplied value as inert terminal text."""
    return _CONTROL_CHARS.sub("", str(value))


# --- Device identity -------------------------------------------------------
# A key only works from devices its owner approved on the dashboard. This
# client keeps a random device token in a private file and sends it with every
# request. A stolen key alone is useless: the thief's machine shows up as a
# new *pending* device the owner won't approve.
DEVICE_TOKEN = None  # loaded in main()
DEVICE_FILE = os.path.join(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "aap", "device"
)


def load_device_token():
    """Read this machine's device token, creating it (mode 600) on first run."""
    try:
        with open(DEVICE_FILE) as f:
            token = f.read().strip()
        if re.fullmatch(r"[0-9a-f]{64}", token):
            return token
    except FileNotFoundError:
        pass
    token = secrets.token_hex(32)
    os.makedirs(os.path.dirname(DEVICE_FILE), mode=0o700, exist_ok=True)
    fd = os.open(DEVICE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    return token


def device_code(token):
    """Pairing code — matches what the dashboard shows for this device."""
    c = hashlib.sha256(token.encode()).hexdigest()[:6].upper()
    return f"{c[:3]}-{c[3:]}"


def auth_headers(api_key, device_token):
    name = re.sub(r"[^A-Za-z0-9._ -]", "", socket.gethostname())[:64] or "unnamed device"
    return {"X-API-Key": api_key, "X-AAP-Device": device_token, "X-AAP-Device-Name": name}


def check_session(base, api_key):
    """Ask whether the key is usable right now.

    Returns (active, retry_after): active is True/False, or None if the server
    couldn't be reached; retry_after is seconds to wait when rate limited.
    """
    try:
        r = requests.get(
            f"{base}/auth/session-status",
            headers=auth_headers(api_key, DEVICE_TOKEN),  # never in the URL
            timeout=5,
        )
    except requests.RequestException as e:
        print(f"\n  ! Could not reach the server at {base}: {safe(e)}")
        return None, 0
    if r.status_code == 429:
        return False, int(r.headers.get("Retry-After", "10"))
    try:
        return bool(r.json().get("active")), 0
    except ValueError:
        return None, 0


def wait_for_session(base, api_key):
    """Poll session-status until the key is usable. Returns True/False."""
    active, _ = check_session(base, api_key)
    if active is None:
        return False
    if active:
        print("✓ Key is active — your account is logged in.")
        return True

    # The server deliberately doesn't say WHY (so a stolen key reveals little).
    print("Key not usable yet. Check that:")
    print(f"  • you're logged in to the web app at {base},")
    print(f"  • this device (code {device_code(DEVICE_TOKEN)}) is approved on your dashboard, and")
    print("  • an admin has enabled your key.")
    try:
        webbrowser.open(base)
    except Exception:
        pass  # headless / no browser — the printed URL is enough

    print("Waiting (Ctrl-C to cancel)", end="", flush=True)
    while True:
        active, retry_after = check_session(base, api_key)
        if active:
            print("\n✓ Key is active — your account is logged in.")
            return True
        time.sleep(max(2, retry_after))
        print(".", end="", flush=True)


def send_message(base, api_key, message):
    """POST the message to the protected endpoint and print the result."""
    try:
        r = requests.post(
            f"{base}/api/message",
            headers=auth_headers(api_key, DEVICE_TOKEN),
            json={"message": message},
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
        print(safe(data.get("reply", data)))
        print(f"  (processed at {safe(data.get('processedAt', 'n/a'))})")
    elif r.status_code == 401:
        print(f"\n401 Unauthorized: {safe(data.get('error', 'No active session found'))}")
    else:
        print(f"\n{r.status_code}: {safe(data.get('error', r.text))}")


def main():
    ap = argparse.ArgumentParser(description="AAP shell client")
    ap.add_argument("--base", default="http://localhost:3000", help="server base URL")
    ap.add_argument(
        "--key",
        help="API key (discouraged: visible in ps/shell history; prefer AAP_API_KEY or the prompt)",
    )
    args = ap.parse_args()
    base = args.base.rstrip("/")

    print("=== Account-Bound API Key Protection — shell client ===\n")
    global DEVICE_TOKEN
    DEVICE_TOKEN = load_device_token()
    print(f"This device's pairing code: {device_code(DEVICE_TOKEN)}\n")

    if args.key:
        print("! Warning: --key is visible in process lists and shell history.\n")
    api_key = (
        args.key
        or os.environ.get("AAP_API_KEY")
        or getpass.getpass("Enter your API key (input hidden): ")
    ).strip()
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
