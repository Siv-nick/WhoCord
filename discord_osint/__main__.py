"""
discord_osint/__main__.py
--------------------------
CLI entry point.

Change log
----------
- ``--token`` is still accepted for backward compatibility, but it now
  prints a warning to stderr that the value is visible in ``ps`` output
  and shell history, and recommends the interactive menu or the
  ``DISCORD_TOKEN`` environment variable instead. The flag is not
  removed because existing scripts may depend on it, but it is no longer
  the recommended path.
- Added ``--hibp-api-key`` for parity with the interactive menu. It has
  the same visibility warning as ``--token``.
- ``--help`` now documents the recommended (env var / interactive) path
  for every credential.
"""

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


def _warn_cli_secret(flag_name: str) -> None:
    """
    Print a one-line warning when a credential is passed on the command
    line. The value is visible in ``ps``, /proc/<pid>/cmdline, and shell
    history.
    """
    print(
        f"[warn] --{flag_name} passed on the command line is visible to "
        f"other local users via `ps` and to anyone with access to your "
        f"shell history. Prefer the interactive menu (option 2) or an "
        f"environment variable (e.g. export {flag_name.upper().replace('-', '_')}=...).",
        file=sys.stderr,
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            'Universal OSINT Pipeline. '
            'Credentials should be set via the interactive menu (option 2) '
            'or via environment variables (DISCORD_TOKEN, GITHUB_TOKEN, '
            'GROQ_API_KEY, HIBP_API_KEY, INSTAGRAM_SESSION). Command-line '
            'flags are supported for scripting but are visible to other '
            'users on the same machine.'
        ),
    )
    parser.add_argument('--version', action='version',
                        version='WhoCord 1.0.3')
    parser.add_argument('--mode', choices=['discord', 'manual'],
                        help='operational mode')
    parser.add_argument('--target',
                        help='manual username or discord user ID')
    parser.add_argument('--token',
                        help='Discord user token (VISIBLE to other local '
                             'users — prefer the env var DISCORD_TOKEN or '
                             'the interactive menu)')
    parser.add_argument('--guild', help='Discord guild ID')
    parser.add_argument('--hibp-api-key',
                        help='HIBP v3 API key (VISIBLE to other local '
                             'users — prefer the env var HIBP_API_KEY)')
    parser.add_argument('--interactive', action='store_true',
                        help='Force interactive menu')
    parser.add_argument('--output',
                        choices=['json', 'markdown', 'html'],
                        default='markdown',
                        help='Report format (default: markdown)')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug verbosity')
    args = parser.parse_args()

    check_dependencies()
    config = Config()

    if args.mode:
        config.MODE = args.mode

    if args.token:
        _warn_cli_secret('token')
        config.DISCORD_TOKEN = args.token

    if args.hibp_api_key:
        _warn_cli_secret('hibp-api-key')
        config.HIBP_API_KEY = args.hibp_api_key

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