import sys
import logging
from .config import Config, SENSITIVE_KEYS
from .tools_config import TOOLS_LIST

def print_menu(config):
    print("\n" + "="*50)
    print("        OSINT IDENTITY PROFILING PIPELINE")
    print("="*50)
    print("1. Toggle investigation tools")
    print("2. Set tokens / API keys")
    print("3. Start investigation")
    print("4. Save config and exit")
    print("5. Toggle debug mode")
    print("="*50)
    show_summary(config)

def show_summary(config):
    print("Current configuration:")
    print(f"  Discord token      : {'set' if config.DISCORD_TOKEN else 'NOT SET'}")
    print(f"  GitHub token       : {'set' if config.GITHUB_TOKEN else 'NOT SET'}")
    print(f"  Groq API key       : {'set' if config.GROQ_API_KEY else 'NOT SET'}")
    print(f"  Instagram session  : {'set' if config.INSTAGRAM_SESSION else 'NOT SET'}")
    print(f"  Debug mode         : {'ON' if getattr(config, 'DEBUG', False) else 'OFF'}")
    enabled = [t[0] for t in TOOLS_LIST if getattr(config, t[0], False)]
    print(f"  Enabled tools      : {len(enabled)} / {len(TOOLS_LIST)}")

def toggle_debug(config):
    current = getattr(config, 'DEBUG', False)
    config.DEBUG = not current
    print(f"Debug mode {'enabled' if not current else 'disabled'}.")
    config.save()

    # Immediately change the log level so --debug and menu toggle behave identically
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
                # Save immediately so the change persists
                config.save()
            else:
                print("Invalid choice.")
        except ValueError:
            print("Enter a number.")

def set_tokens(config):
    print("\n--- Set Tokens / API Keys ---")
    print("Leave blank to keep current value.\n")
    disc = input(f"Discord token [{config.DISCORD_TOKEN[:10] + '...' if config.DISCORD_TOKEN else 'empty'}]: ").strip()
    if disc:
        config.DISCORD_TOKEN = disc
    gh = input(f"GitHub token [{config.GITHUB_TOKEN[:10] + '...' if config.GITHUB_TOKEN else 'empty'}]: ").strip()
    if gh:
        config.GITHUB_TOKEN = gh
    groq = input(f"Groq API key [{config.GROQ_API_KEY[:10] + '...' if config.GROQ_API_KEY else 'empty'}]: ").strip()
    if groq:
        config.GROQ_API_KEY = groq
    insta = input(f"Instagram session [{config.INSTAGRAM_SESSION[:10] + '...' if config.INSTAGRAM_SESSION else 'empty'}]: ").strip()
    if insta:
        config.INSTAGRAM_SESSION = insta
    config.save()
    print("Tokens updated and saved.")

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
