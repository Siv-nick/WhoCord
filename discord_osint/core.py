"""
discord_osint/core.py
----------------------
InvestigationCore – the per-investigation intel accumulator.

Permissions
-----------
The cache directory is created with mode 0700 and chmod'd on entry.
Intel snapshots contain the target's emails, breach data, and
identity clues; on a shared workstation they must not be readable by
other local users. Each snapshot file is chmod'd to 0600 after write.

Change log
----------
- ``load_latest_state()`` no longer uses a bare ``except:`` around the
  file read. A corrupt / partially-written intel snapshot prints a
  warning on stderr instead of silently returning ``None``.
- ``cache_dir`` gets mode 0700; snapshot files get mode 0600.
"""

import os
import json
import glob
import sys
from datetime import datetime

from .utils import CACHE_DIR


class InvestigationCore:
    def __init__(self, target_id, cache_dir=CACHE_DIR):
        self.target_id = target_id
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(cache_dir, 0o700)
        except OSError:
            pass
        self.intel = {
            "discord": {},
            "social_profiles": {},
            "emails": {},
            "breaches": {},
            "identity_clues": {},
            "timeline": [],
            "confidence_scores": {},
        }

    def add_intel(self, cat, key, value, conf="medium", source=None):
        if cat not in self.intel:
            self.intel[cat] = {}
        self.intel[cat][key] = {
            "value": value,
            "confidence": conf,
            "source": source,
            "timestamp": datetime.now().isoformat(),
        }
        self.intel["timeline"].append(f"[{cat}] {key}: {value} (conf: {conf})")

    def save_state(self):
        fn = os.path.join(
            self.cache_dir,
            f"intel_{self.target_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(self.intel, f, indent=2)
        try:
            os.chmod(fn, 0o600)
        except OSError:
            pass
        return fn

    def load_latest_state(self):
        pattern = os.path.join(self.cache_dir, f"intel_{self.target_id}_*.json")
        files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
        if not files:
            return None

        latest = files[0]
        try:
            with open(latest, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            print(
                f"[core] WARNING: could not read cached intel at {latest!r}: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return None
        except Exception as exc:
            print(
                f"[core] WARNING: unexpected error reading {latest!r}: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return None