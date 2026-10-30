#!/usr/bin/env python3
"""
AAP shell — the account-bound API client.

Before any call, the server checks that the key's owner is logged in to the
web app, that this device is approved, and that the request fits the key's
scopes and limits. This client walks you through that, then gives you a
streaming chat with the engine (local rules + LLM).

Usage:
    python3 client.py                          # interactive (key prompt is hidden)
    AAP_API_KEY=ak_... python3 client.py       # key from the environment
    python3 client.py -p "explain CSRF"        # one-shot: print the answer and exit
    python3 client.py --base http://host:3000 --no-stream

The key is sent only in the X-API-Key header. Avoid --key: command-line
arguments are visible in `ps` and saved in shell history.

Requires the `requests` library:  pip install requests
"""

import argparse
import getpass
import hashlib
import itertools
import json
import os
import re
import secrets
import shutil
import socket
import sys
import threading
import time
import webbrowser

try:
    import requests
except ImportError:
    sys.exit("This client needs the 'requests' library:  pip install requests")


# --- Output safety -----------------------------------------------------------
# Server-supplied text (replies echo user input) must not be able to inject
# ANSI/OSC escape sequences that rewrite the screen, retitle the window, or
# plant clickable links. Strip C0/C1 control characters (keeping newline and
# tab) before printing anything from the server.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def safe(value):
    """Render a server-supplied value as inert terminal text."""
    return _CONTROL_CHARS.sub("", str(value))


# --- Styling -----------------------------------------------------------------
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


def _sgr(code):
    return (lambda s: f"\033[{code}m{s}\033[0m") if COLOR else (lambda s: s)


bold, dim = _sgr("1"), _sgr("2")
teal, violet, green, red, amber, cyan = (
    _sgr("38;5;37"), _sgr("38;5;141"), _sgr("38;5;78"), _sgr("38;5;203"), _sgr("38;5;214"), _sgr("38;5;81"),
)
ACCENT = teal
OK, BAD, WARN, INFO = green("✓"), red("✗"), amber("!"), teal("•")
_ANSI = re.compile(r"\033\[[0-9;]*m")


def width():
    return max(48, min(shutil.get_terminal_size((88, 24)).columns, 100))


def visible_len(s):
    return len(_ANSI.sub("", s))


def clip(s, n):
    """Shorten plain text to n visible chars with an ellipsis."""
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def panel(title, rows):
    """Rounded box with a title in the top border. Rows are (style, text) pairs."""
    w = width() - 2
    print(ACCENT("╭─ ") + bold(title) + " " + ACCENT("─" * max(0, w - visible_len(title) - 4) + "╮"))
    for style, text in rows:
        text = clip(text, w - 3)
        print(ACCENT("│") + " " + style(text) + " " * max(0, w - 2 - len(text)) + ACCENT("│"))
    print(ACCENT("╰" + "─" * (w - 1) + "╯"))


def rule():
    if COLOR:
        print(dim("─" * width()))


def meter(used, limit, cells=22):
    """Usage bar: green → amber → red as the limit gets close."""
    if not isinstance(limit, int):
        return dim("unlimited".ljust(cells)) + f"  {used:,}"
    frac = min(1.0, used / limit) if limit else 1.0
    filled = round(frac * cells)
    color = green if frac < 0.7 else amber if frac < 0.9 else red
    return color("█" * filled) + dim("░" * (cells - filled)) + f"  {used:,} / {limit:,}"


class Spinner:
    """Spinner shown until the first streamed text arrives (TTY only)."""

    FRAMES = "◐◓◑◒"

    def __init__(self, label):
        self.label, self._stop, self._t = label, threading.Event(), None

    def set(self, label):
        """Change the label while spinning (e.g. what we're waiting for)."""
        self.label = label

    def __enter__(self):
        if COLOR:
            self._t = threading.Thread(target=self._run, daemon=True)
            self._t.start()
        return self

    def _run(self):
        for frame in itertools.cycle(self.FRAMES):
            if self._stop.is_set():
                break
            sys.stdout.write(f"\r\033[2K  {violet(frame)} {dim(self.label)}")
            sys.stdout.flush()
            time.sleep(0.09)

    def stop(self):
        if self._t and not self._stop.is_set():
            self._stop.set()
            self._t.join()
            sys.stdout.write("\r\033[2K")
            sys.stdout.flush()

    def __exit__(self, *exc):
        self.stop()


class MarkdownStream:
    """
    Streaming renderer for a light subset of markdown, safe on arbitrary chunk
    boundaries: fenced code blocks get a gutter and colour, **bold** and
    `inline code` are styled. Everything passes through safe() first.
    """

    def __init__(self, indent="  "):
        self.indent = indent
        self.in_code = False
        self.bold = False
        self.inline = False
        self.line_start = True
        self.linebuf = ""  # start of the current line, held back to spot ``` fences
        self.pending = ""  # a single '*' that might become '**'

    def feed(self, text):
        for ch in safe(text):
            self._char(ch)
        sys.stdout.flush()

    def _out(self, s):
        sys.stdout.write(s)

    def _begin_line(self):
        self._out(self.indent)
        if self.in_code:
            # Gutter, then colour the whole code line in one go.
            self._out(dim("│ ") + ("\033[38;5;81m" if COLOR else ""))
        self.line_start = False

    def _newline(self):
        if self.in_code and COLOR:
            self._out("\033[0m")
        self._out("\n")
        self.line_start = True

    def _char(self, ch):
        if self.line_start:
            if ch == "\n":
                self._end_line()
                return
            self.linebuf += ch
            if "```".startswith(self.linebuf) or self.linebuf.startswith("```"):
                return  # might be / is a fence: hold until newline (language tag)
            if not self.in_code:
                if set(self.linebuf) == {"="}:
                    return  # possible "====" heading underline: hold
                if self.linebuf in ("*", "-"):
                    return  # possible list bullet: wait for the next char
                if self.linebuf in ("* ", "- "):
                    self.linebuf = ""
                    self._begin_line()
                    self._out(ACCENT("•") + " ")
                    return
            text, self.linebuf = self.linebuf, ""
            self._begin_line()
            self._emit(text)
            return
        if ch == "\n":
            self._flush_pending()
            self._newline()
            return
        self._emit(ch)

    def _end_line(self):
        """Newline while still at line start: either a fence or an empty line."""
        text, self.linebuf = self.linebuf, ""
        if not self.in_code and len(text) >= 3 and set(text) == {"="}:
            return  # heading underline — the heading above is already bold
        if text.startswith("```"):
            lang = text[3:].strip()
            self.in_code = not self.in_code
            if self.in_code:
                self._out(self.indent + dim("┌ " + (lang or "code")) + "\n")
            else:
                self._out(self.indent + dim("└") + "\n")
            return
        if text or self.in_code:  # keep the gutter on blank code lines
            self._begin_line()
            self._emit(text)
        self._newline()

    def _emit(self, text):
        for ch in text:
            if self.in_code:
                self._out(ch)  # line colour already set in _begin_line
                continue
            if ch == "*":
                self.pending += "*"
                if self.pending == "**":
                    self.bold = not self.bold
                    self.pending = ""
                    if COLOR:
                        self._out("\033[1m" if self.bold else "\033[22m")
                continue
            self._flush_pending()
            if ch == "`":
                self.inline = not self.inline
                if COLOR:
                    self._out("\033[38;5;81m" if self.inline else "\033[39m")
                continue
            self._out(ch)

    def _flush_pending(self):
        if self.pending:
            self._out(self.pending)
            self.pending = ""

    def close(self):
        if self.linebuf:
            self._begin_line()
            self._emit(self.linebuf)
            self.linebuf = ""
        self._flush_pending()
        if COLOR:
            self._out("\033[0m")
        if not self.line_start:
            self._out("\n")
        sys.stdout.flush()


# --- Device identity -----------------------------------------------------------
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


# --- Server calls ----------------------------------------------------------------
class Client:
    def __init__(self, base, api_key):
        self.base, self.api_key = base, api_key

    def headers(self):
        return auth_headers(self.api_key, DEVICE_TOKEN)

    def get(self, path, timeout=8):
        return requests.get(f"{self.base}{path}", headers=self.headers(), timeout=timeout)

    def session_active(self):
        """(active, retry_after, reason). active is None if the server is unreachable.
        reason (only for this owner's approved devices) says what's missing."""
        try:
            r = self.get("/auth/session-status", timeout=5)
        except requests.RequestException:
            return None, 0, None
        if r.status_code == 429:
            return False, int(r.headers.get("Retry-After", "10")), None
        try:
            d = r.json()
        except ValueError:
            return None, 0, None
        return bool(d.get("active")), 0, d.get("reason")


def waiting_text(reason, base):
    """What we're waiting for, in plain words (shown next to the spinner)."""
    code = device_code(DEVICE_TOKEN)
    return {
        "device_not_approved": f"approve device {code} on your dashboard ({base})",
        "no_session": f"log in to the web app at {base}",
        "key_disabled": "an admin must enable your key",
        "key_locked_needs_approval": "key locked — waiting for your org admin to approve regeneration",
    }.get(reason, f"waiting for the server ({base})")


def recover_locked_key(client):
    """The key was auto-locked: guide the owner to a new key, then use it."""
    print()
    print(f"  {BAD} {bold('Your key was locked automatically')} after suspected compromise or abuse.")
    print(f"      {INFO} Log in at {ACCENT(client.base)} and click {bold('Generate new key')} (your password).")
    print(f"      {INFO} Or ask an admin to unlock it if this was a false alarm.")
    if not sys.stdin.isatty():
        return False
    try:
        new_key = getpass.getpass("  Paste the new key (hidden), or press Enter to keep waiting: ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    if new_key:
        client.api_key = new_key
        print(f"  {OK} Using the new key.")
    return True


def wait_for_session(client, quiet=False):
    """Block until the key is usable, explaining what's missing as it changes.
    Returns True when active, False if the server is unreachable or on Ctrl-C."""
    active, _, reason = client.session_active()
    if active is None:
        print(f"  {BAD} Can't reach the server at {client.base}")
        return False
    if active:
        return True
    if not quiet and reason in ("device_not_approved", "no_session", None):
        try:
            webbrowser.open(client.base)
        except Exception:
            pass
    shown = None
    try:
        while not active:
            if reason == "key_locked":
                if not recover_locked_key(client):
                    return False
                active, _, reason = client.session_active()
                continue
            label = waiting_text(reason, client.base)
            if label != shown:
                if not COLOR:
                    print(f"  {WARN} {label}")
                shown = label
            with Spinner(label + " · Ctrl-C to cancel") as spin:
                while True:
                    time.sleep(2)
                    active, retry, new_reason = client.session_active()
                    if retry:
                        time.sleep(retry)
                    if active or new_reason != reason:
                        reason = new_reason
                        break
                    spin.set(label + " · Ctrl-C to cancel")
            if not active and COLOR:
                print(f"  {OK} {dim(shown)}")  # that step is done; the next one is shown
    except KeyboardInterrupt:
        print()
        return False
    print(f"  {OK} Key is active.")
    return True


def show_error(r):
    try:
        msg = r.json().get("error", r.text)
    except ValueError:
        msg = r.text
    hint = ""
    if r.status_code == 403 and "device" in str(msg):
        hint = f" — approve code {bold(device_code(DEVICE_TOKEN))} on your dashboard"
    elif r.status_code == 429:
        hint = f" — retry in {r.headers.get('Retry-After', '?')}s"
    print(f"  {BAD} {red(str(r.status_code))} {safe(msg)}{hint}")


# --- Slash commands ---------------------------------------------------------------
HELP = [
    ("/help", "show this list"),
    ("/usage", "your scopes, limits and usage"),
    ("/model", "engine and model in use"),
    ("/device", "this device's pairing code"),
    ("/clear", "forget the conversation so far"),
    ("/save <file>", "save the conversation as markdown"),
    ("/status", "re-check session and device"),
    ("/exit", "quit (also Ctrl-D)"),
]


def cmd_usage(client):
    r = client.get("/api/usage")
    if r.status_code != 200:
        return show_error(r)
    d = r.json()
    lim, u = d.get("limits", {}), d["usage"]
    acct = f"{d['org']['name']} · {d['org']['role']}" if d.get("org") else "personal"
    print(f"  {bold('Account')}  {safe(acct)}")
    print(f"  {bold('Scopes')}   " + " ".join(violet(safe(s)) for s in d["scopes"]))
    print(f"  {bold('LLM')}      " + (green("allowed") if d.get("llm") else amber("not allowed — local engine only")))
    print()
    for label, used, cap in (
        ("requests today ", u["today"]["requests"], lim.get("requestsPerDay")),
        ("requests month ", u["month"]["requests"], lim.get("requestsPerMonth")),
        ("tokens today   ", u["today"]["tokens"], lim.get("tokensPerDay")),
        ("tokens month   ", u["month"]["tokens"], lim.get("tokensPerMonth")),
    ):
        print(f"  {dim(label)} {meter(used, cap)}")
    by_cat = u["today"]["byCategory"]
    if by_cat:
        cats = ", ".join(f"{safe(k)} {v}" for k, v in sorted(by_cat.items(), key=lambda x: -x[1]))
        print(f"  {dim('by category    ')} {cats}")


def cmd_model(client):
    r = client.get("/api/engine")
    if r.status_code != 200:
        return show_error(r)
    d = r.json()
    if not d.get("enabled"):
        print(f"  {INFO} LLM disabled on the server — local engine only")
        return
    state = green("online") if d.get("reachable") else red("unreachable — local fallback in use")
    print(f"  {bold('Provider')} {safe(d['provider'])} ({state})")
    print(f"  {bold('Model')}    {safe(d['model'])}")
    for cat, model in (d.get("routes") or {}).items():
        print(f"  {dim('  ' + cat.ljust(8))} {safe(model)}")
    if d.get("missing"):
        print(f"  {WARN} not installed on the server: {safe(', '.join(d['missing']))}")


def save_transcript(path, history):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# AAP conversation — {time.strftime('%Y-%m-%d %H:%M')}\n\n")
        for turn in history:
            who = "You" if turn["role"] == "user" else "Assistant"
            f.write(f"**{who}:**\n\n{turn['content']}\n\n")


# --- Chat -------------------------------------------------------------------------
MAX_HISTORY = 12  # messages (6 exchanges) sent for context


def ask(client, message, history, stream=True):
    """Send one message and render the reply. Returns (reply, ok, status)."""
    body = {"message": message, "history": history[-MAX_HISTORY:], "stream": stream}
    started = time.time()
    try:
        r = requests.post(
            f"{client.base}/api/message", headers=client.headers(), json=body, timeout=180, stream=stream
        )
    except requests.RequestException as e:
        print(f"  {BAD} Request failed: {safe(e)}")
        return None, False, 0
    if r.status_code != 200:
        show_error(r)
        return None, False, r.status_code

    reply, meta = "", {}
    md = MarkdownStream()
    if stream:
        with Spinner("thinking…") as spin:
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                evt = json.loads(line)
                if evt.get("type") == "delta":
                    spin.stop()
                    reply += evt["text"]
                    md.feed(evt["text"])
                elif evt.get("type") == "done":
                    meta = evt
    else:
        d = r.json()
        reply, meta = d.get("reply", ""), d
        md.feed(reply)
    md.close()

    took = meta.get("ms", int((time.time() - started) * 1000)) / 1000
    parts = [safe(meta.get("category", "?")), safe(meta.get("source", "?"))]
    if meta.get("model"):
        parts.append(safe(meta["model"]))
    parts += [f"{meta.get('tokens', 0):,} tok", f"{took:.1f}s"]
    if meta.get("truncated"):
        parts.append(amber("truncated — ask me to continue"))
    print(dim("  ↳ " + " · ".join(parts)))
    return reply, True, 200


def repl(client, stream):
    history = []
    print(dim("  /help for commands · Ctrl-D to exit"))
    while True:
        print()
        rule()
        try:
            line = input(ACCENT("› ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            if not sys.stdin.isatty():
                return  # piped input: a blank line ends the session
            continue

        if line.startswith("/"):
            cmd, _, arg = line.partition(" ")
            if cmd in ("/exit", "/quit"):
                return
            elif cmd == "/help":
                for name, desc in HELP:
                    print(f"  {violet(name.ljust(14))} {dim(desc)}")
            elif cmd == "/usage":
                cmd_usage(client)
            elif cmd == "/model":
                cmd_model(client)
            elif cmd == "/device":
                print(f"  {bold('Pairing code')} {bold(device_code(DEVICE_TOKEN))}  {dim(DEVICE_FILE)}")
            elif cmd == "/clear":
                history.clear()
                print(f"  {OK} Conversation cleared.")
            elif cmd == "/save":
                if not arg.strip():
                    print(f"  {WARN} Usage: /save <file.md>")
                else:
                    save_transcript(arg.strip(), history)
                    print(f"  {OK} Saved {len(history)} messages to {arg.strip()}")
            elif cmd == "/status":
                if wait_for_session(client):
                    print(f"  {OK} Logged in · device approved · key enabled")
            else:
                print(f"  {WARN} Unknown command {safe(cmd)} — try /help")
            continue

        print()
        reply, ok, status = ask(client, line, history, stream)
        if ok:
            history += [{"role": "user", "content": line}, {"role": "assistant", "content": reply}]
            del history[:-MAX_HISTORY]
        elif status in (401, 403) and wait_for_session(client, quiet=True):
            # Logged out, device removed, key disabled or locked: wait_for_session
            # explains what's missing and resumes once it's fixed.
            print(dim("  Ready again — send your message again."))


# --- Entry point ------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="AAP shell — account-bound API client")
    ap.add_argument("--base", default="http://localhost:3000", help="server base URL")
    ap.add_argument(
        "--key",
        help="API key (discouraged: visible in ps/shell history; prefer AAP_API_KEY or the prompt)",
    )
    ap.add_argument("-p", "--print", dest="prompt", help="one-shot: send PROMPT, print the answer, exit")
    ap.add_argument("--no-stream", action="store_true", help="wait for the full answer instead of streaming")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    global DEVICE_TOKEN
    DEVICE_TOKEN = load_device_token()

    if args.key:
        print(f"{WARN} --key is visible in process lists and shell history.")
    api_key = (
        args.key or os.environ.get("AAP_API_KEY") or getpass.getpass("API key (input hidden): ")
    ).strip()
    if not api_key:
        sys.exit("No API key provided.")
    client = Client(base, api_key)

    if args.prompt:  # one-shot mode for scripts
        if not wait_for_session(client, quiet=True):
            sys.exit(1)
        _, ok, _ = ask(client, args.prompt, [], stream=not args.no_stream)
        sys.exit(0 if ok else 1)

    print()
    plain = lambda s: s
    panel(
        "◆ AAP shell",
        [
            (dim, "Account-bound API client — your key only works while you're logged in."),
            (plain, ""),
            (plain, f"server   {safe(base)}"),
            (plain, f"device   {device_code(DEVICE_TOKEN)}  ({DEVICE_FILE.replace(os.path.expanduser('~'), '~')})"),
        ],
    )
    print()
    if not wait_for_session(client):
        sys.exit(1)
    print(f"  {OK} Logged in · device approved · key enabled")
    try:
        r = client.get("/api/engine")
        if r.status_code == 200 and r.json().get("enabled"):
            e = r.json()
            state = green("online") if e.get("reachable") else amber("offline, local fallback")
            print(f"  {OK} Engine {safe(e['provider'])} · {safe(e['model'])} ({state})")
    except (requests.RequestException, ValueError):
        pass

    try:
        repl(client, stream=not args.no_stream)
    except KeyboardInterrupt:
        print()
    print(dim("  bye"))


if __name__ == "__main__":
    main()
