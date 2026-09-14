"""
discord_osint/ui.py
-------------------
Interactive CLI menu.

Change log
----------
- Token entry now uses ``getpass.getpass()`` instead of ``input()``.
- Added an explicit per-field clear path (`!clear`).
- HIBP_API_KEY is settable from the menu.
- APOLLO_API_KEY and LUSHA_API_KEY are now settable from the menu. Both
  are labelled to make their paid-credit nature explicit at the point of
  entry.
"""

import getpass
import logging
import sys

from .config import Config, SENSITIVE_KEYS
from .tools_config import TOOLS_LIST


_TOKEN_LABELS = {
    "DISCORD_TOKEN":     "Discord token",
    "GITHUB_TOKEN":      "GitHub token",
    "GROQ_API_KEY":      "Groq API key",
    "OPENROUTER_API_KEY": "OpenRouter API key",
    "HIBP_API_KEY":      "HIBP API key (v3, required for breach lookup)",
    "INSTAGRAM_SESSION": "Instagram session",
    "APOLLO_API_KEY":    "Apollo.io API key (paid credits)",
    "LUSHA_API_KEY":     "Lusha API key (paid credits)",
}


def _mask(value: str) -> str:
    if not value:
        return "empty"
    return "stored"


def print_menu(config):
    print("\n" + "=" * 50)
    print("        OSINT IDENTITY PROFILING PIPELINE")
    print("=" * 50)
    print("1. Toggle investigation tools")
    print("2. Set tokens / API keys")
    print("3. Start investigation")
    print("4. Save config and exit")
    print("5. Toggle debug mode")
    print("6. Upgrade external tools")
    print("=" * 50)
    show_summary(config)


def show_summary(config):
    print("Current configuration:")
    for key in ("DISCORD_TOKEN", "GITHUB_TOKEN", "GROQ_API_KEY",
                "OPENROUTER_API_KEY", "HIBP_API_KEY", "INSTAGRAM_SESSION",
                "APOLLO_API_KEY", "LUSHA_API_KEY"):
        value = getattr(config, key, "") or ""
        label = _TOKEN_LABELS.get(key, key)
        state = _mask(value)
        print(f"  {label:<48}: {state}")
    print(f"  Debug mode                                      : "
          f"{'ON' if getattr(config, 'DEBUG', False) else 'OFF'}")
    enabled = [t[0] for t in TOOLS_LIST if getattr(config, t[0], False)]
    print(f"  Enabled tools                                   : "
          f"{len(enabled)} / {len(TOOLS_LIST)}")


def toggle_debug(config):
    current = getattr(config, 'DEBUG', False)
    config.DEBUG = not current
    print(f"Debug mode {'enabled' if not current else 'disabled'}.")
    config.save()

    level = logging.DEBUG if config.DEBUG else logging.INFO
    logging.getLogger().setLevel(level)


def toggle_tools(config):
    while True:
        print("\n--- Toggle Tools ---")
        for idx, (key, desc) in enumerate(TOOLS_LIST, 1):
            status = "ON" if getattr(config, key, False) else "OFF"
            print(f"{idx:2d}. [{status}] {desc}")
        print(" 0. Back to main menu")
        choice = input("Enter number to toggle: ").strip()
        if choice == "0":
            break
        try:
            num = int(choice) - 1
            if 0 <= num < len(TOOLS_LIST):
                key = TOOLS_LIST[num][0]
                current = getattr(config, key, False)
                setattr(config, key, not current)
                print(f"  {TOOLS_LIST[num][1]} -> {'ON' if not current else 'OFF'}")
                config.save()
            else:
                print("Invalid choice.")
        except ValueError:
            print("Enter a number.")


def _prompt_secret(label: str, current_present: bool) -> tuple[str, bool]:
    marker = "stored" if current_present else "empty"
    try:
        raw = getpass.getpass(
            f"{label} [{marker}] "
            f"(Enter=keep, '!clear'=remove, or paste new value): "
        )
    except (EOFError, KeyboardInterrupt):
        print()
        return "", False

    stripped = raw.strip()
    if stripped == "!clear":
        return "", True
    if not stripped:
        return "", False
    return stripped, False


def set_tokens(config):
    print("\n--- Set Tokens / API Keys ---")
    print("Values are entered without echo. Press Enter to keep the current value.")
    print("Type !clear to remove a stored value.\n")

    changed = False
    for key in SENSITIVE_KEYS:
        label = _TOKEN_LABELS.get(key, key)
        current_present = bool(getattr(config, key, ""))
        value, clear = _prompt_secret(label, current_present)

        if clear:
            setattr(config, key, "")
            print(f"  {label}: cleared")
            changed = True
        elif value:
            setattr(config, key, value)
            print(f"  {label}: updated")
            changed = True
        else:
            print(f"  {label}: unchanged")

    if changed:
        config.save()
        print("Tokens updated and saved.")
    else:
        print("No changes.")


def start_pipeline(config):
    print("\n--- Start Investigation ---")
    print("Select mode:")
    print("1. Manual (investigate a username)")
    print("2. Discord (investigate a Discord user)")
    mode_choice = input("Choice (1/2): ").strip()
    if mode_choice == "1":
        config.MODE = "manual"
        uname = input("Enter the username to investigate: ").strip()
        if uname:
            config.MANUAL_USERNAME = uname
        email = input("Enter an email to investigate (optional, press Enter to skip): ").strip()
        if email:
            config.MANUAL_EMAIL = email
        if not uname and not email:
            print("You must enter at least a username or an email."); return
    elif mode_choice == "2":
        config.MODE = "discord"
        print("\nMulti‑guild search: The script will search all guilds you are a member of")
        print("for links shared by the target. This may increase run time and API load.")
        multi = input("Enable multi‑guild search? (y/n): ").strip().lower()
        config.MULTI_GUILD_SEARCH = (multi == 'y')
        try:
            guild_id = int(input("Target's guild/server ID: ").strip())
            user_id = int(input("Target's user ID: ").strip())
            config.TARGET_USER_ID = user_id
            config.TARGET_GUILD_ID = guild_id
        except ValueError:
            print("IDs must be integers."); return
        extras = input("Additional usernames or emails to search (comma‑separated, optional): ").strip()
        if extras:
            config.EXTRA_TARGETS = [t.strip() for t in extras.split(",") if t.strip()]
    else:
        print("Invalid choice."); return

    if config.MODE == "discord" and not config.DISCORD_TOKEN:
        print("ERROR: Discord token is not set. Set it in menu option 2 first.")
        return

    print("\nConfiguration applied. Starting investigation...\n")
    from .pipeline import run_osint_pipeline
    run_osint_pipeline(config)