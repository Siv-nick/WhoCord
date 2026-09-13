import os
import json
import glob
from datetime import datetime
from .utils import CACHE_DIR

class InvestigationCore:
    def __init__(self, target_id, cache_dir=CACHE_DIR):
        self.target_id = target_id
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        self.intel = {
            "discord":{}, "social_profiles":{}, "emails":{}, "breaches":{},
            "identity_clues":{}, "timeline":[], "confidence_scores":{}
        }
    def add_intel(self, cat, key, value, conf="medium", source=None):
        if cat not in self.intel: self.intel[cat]={}
        self.intel[cat][key] = {"value":value,"confidence":conf,"source":source,"timestamp":datetime.now().isoformat()}
        self.intel["timeline"].append(f"[{cat}] {key}: {value} (conf: {conf})")
    def save_state(self):
        fn = os.path.join(self.cache_dir, f"intel_{self.target_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(fn,'w') as f: json.dump(self.intel, f, indent=2)
        return fn
    def load_latest_state(self):
        pattern = os.path.join(self.cache_dir, f"intel_{self.target_id}_*.json")
        files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
        if files:
            try:
                with open(files[0], 'r') as f:
                    return json.load(f)
            except: pass
        return None