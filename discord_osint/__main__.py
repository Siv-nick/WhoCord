import sys
import os
import pathlib
import shutil
import argparse

# ---- Make bundled tools available ----
if getattr(sys, 'frozen', False):
    tool_dir = os.path.dirname(sys.executable)
    os.environ["PATH"] = tool_dir + os.pathsep + os.environ.get("PATH", "")

# ---- Clear stale bytecode cache ----
def clear_pycache():
    root = pathlib.Path(__file__).resolve().parent
    for pycache in root.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache)
clear_pycache()

from .config import Config
from .ui import print_menu, toggle_tools, set_tokens, start_pipeline, toggle_debug
from .pipeline import run_osint_pipeline
from .utils import check_dependencies

def main():
    parser = argparse.ArgumentParser(description='Universal OSINT Pipeline')
    parser.add_argument('--version', action='version',
                        version='WhoCord 1.0.3')
    parser.add_argument('--mode', choices=['discord','manual'], help='operational mode')
    parser.add_argument('--target', help='manual username or discord user ID')
    parser.add_argument('--token', help='Discord user token')
    parser.add_argument('--guild', help='Discord guild ID')
    parser.add_argument('--interactive', action='store_true', help='Force interactive menu')
    parser.add_argument('--output', choices=['json','markdown','html'], default='markdown',
                        help='Report format (default: markdown)')
    parser.add_argument('--debug', action='store_true', help='Enable debug verbosity')
    args = parser.parse_args()

    check_dependencies()
    config = Config()

    if args.mode:
        config.MODE = args.mode
    if args.token:
        config.DISCORD_TOKEN = args.token
    if args.guild:
        config.TARGET_GUILD_ID = int(args.guild)
    if args.target:
        if config.MODE == 'manual':
            config.MANUAL_USERNAME = args.target
        elif config.MODE == 'discord' and args.target.isdigit():
            config.TARGET_USER_ID = int(args.target)

    config.OUTPUT_FORMAT = args.output
    if args.debug:
        config.DEBUG = True

    from .logger import setup_logging
    setup_logging(config.DEBUG)

    if args.interactive or (len(sys.argv) == 1 and not args.mode):
        while True:
            print_menu(config)
            choice = input(">> ").strip()
            if choice == '1':
                toggle_tools(config)
            elif choice == '2':
                set_tokens(config)
            elif choice == '3':
                start_pipeline(config)
                print("\nInvestigation complete. Goodbye.")
                break
            elif choice == '4':
                config.save()
                print("Config saved. Exiting.")
                sys.exit(0)
            elif choice == '5':
                toggle_debug(config)
            elif choice == '6':
                from .utils import upgrade_tools
                upgrade_tools()
            else:
                print("Invalid option.")
    else:
        run_osint_pipeline(config)

if __name__ == "__main__":
    main()
