"""
discord_osint/core.py
----------------------
InvestigationCore – the per-investigation intel accumulator.

Change log
----------
- ``load_latest_state()`` no longer uses a bare ``except:`` around the
  file read. A corrupt / partially-written intel snapshot now prints a
  warning on stderr instead of silently returning ``None`` (which the
  caller would interpret as "no prior intel," potentially discarding
  usable case data without any trace).
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
        os.makedirs(cache_dir, exist_ok=True)
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
            # A corrupt or partially-written snapshot used to vanish into
            # a bare `except: pass`. Surface it so the operator knows the
            # cached state was not applied.
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