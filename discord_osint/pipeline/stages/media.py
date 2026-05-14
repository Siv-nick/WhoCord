"""
discord_osint/pipeline/stages/media.py
---------------------------------------
MediaStage – download avatar images, extract EXIF metadata, and
optionally run reverse-image search.

Reads from ctx
--------------
ctx.avatar_urls   – populated by DiscordModeStage and ScrapingStage

Writes to ctx
-------------
ctx.intel_core    – EXIF GPS coords, camera model, date taken,
                    reverse-image search domain hits
"""

from __future__ import annotations

import os

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...utils import CACHE_DIR
from ...extras import download_avatar, extract_metadata, reverse_image_search


class MediaStage(Stage):
    name = "media"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        cfg = ctx.config

        if not ctx.avatar_urls:
            print("\n-- Media: no avatar URLs collected, skipping --")
            return

        print(f"\n-- EXIF & reverse image ({len(ctx.avatar_urls)} avatar(s)) --")
        emit("progress", {"message": f"Processing {len(ctx.avatar_urls)} avatar image(s)"})

        avatar_dir = os.path.join(CACHE_DIR, "avatars")
        os.makedirs(avatar_dir, exist_ok=True)

        avatar_files: list[str] = []
        for avatar_url in ctx.avatar_urls:
            fpath = download_avatar(avatar_url, avatar_dir)
            if fpath:
                avatar_files.append(fpath)
                emit("finding", {"type": "avatar_downloaded", "path": fpath})

        for fpath in avatar_files:
            fname = os.path.basename(fpath)

            # ---------------------------------------------------------------- #
            # EXIF extraction                                                  #
            # ---------------------------------------------------------------- #
            if cfg.ENABLE_EXIF:
                meta = extract_metadata(fpath)
                if meta:
                    gps = meta.get("gps")
                    if gps:
                        ctx.intel_core.add_intel(
                            "media", f"exif_gps_{fname}", gps, source="exif"
                        )
                        emit("finding", {
                            "type": "exif_gps",
                            "file": fname,
                            "value": gps,
                        })
                    date_taken = meta.get("date_taken")
                    if date_taken:
                        ctx.intel_core.add_intel(
                            "media", f"exif_date_{fname}", date_taken, source="exif"
                        )
                    camera = meta.get("camera")
                    if camera:
                        ctx.intel_core.add_intel(
                            "media", f"exif_camera_{fname}", camera, source="exif"
                        )

            # ---------------------------------------------------------------- #
            # Reverse image search                                             #
            # ---------------------------------------------------------------- #
            if cfg.ENABLE_REVERSE_IMG:
                results = reverse_image_search(fpath)
                if results:
                    ctx.intel_core.add_intel(
                        "media", f"reverse_img_{fname}", results, source="saucenao"
                    )
                    emit("finding", {
                        "type": "reverse_image",
                        "file": fname,
                        "domains": results,
                    })
                    print(f"  Reverse image match domains: {results}")

        print(f"  Media stage complete. {len(avatar_files)} image(s) processed.")
