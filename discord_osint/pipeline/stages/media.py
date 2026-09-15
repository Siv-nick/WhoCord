"""
discord_osint/pipeline/stages/media.py
---------------------------------------
MediaStage – download avatar images, extract EXIF metadata, and
optionally run reverse-image search.

Permissions
-----------
The avatars directory is created with mode 0700 and chmod'd on entry
so cached images — which contain the target's photographs and
sometimes GPS EXIF — are not readable by other local users on a
shared workstation. Individual files are chmod'd to 0600 by
``download_avatar``.
"""

from __future__ import annotations

import os

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...utils import CACHE_DIR, log_trace
from ...extras import (
    download_avatar,
    extract_metadata,
    reverse_image_search,
    reverse_image_search_tineye,
)


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
        os.makedirs(avatar_dir, mode=0o700, exist_ok=True)
        try:
            os.chmod(avatar_dir, 0o700)
        except OSError:
            pass

        avatar_files: list[str] = []
        for avatar_url in ctx.avatar_urls:
            fpath = download_avatar(avatar_url, avatar_dir)
            if fpath:
                avatar_files.append(fpath)
                emit("finding", {"type": "avatar_downloaded", "path": fpath})

        tineye_key = (
            getattr(cfg, "TINEYE_API_KEY", "") or ""
        ) if getattr(cfg, "ENABLE_TINEYE", False) else ""

        for fpath in avatar_files:
            fname = os.path.basename(fpath)

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

            if cfg.ENABLE_REVERSE_IMG:
                saucenao_results: list[str] = []
                try:
                    saucenao_results = reverse_image_search(fpath) or []
                except Exception as exc:
                    log_trace(f"MediaStage: saucenao raised "
                              f"{type(exc).__name__}: {exc}")

                if saucenao_results:
                    ctx.intel_core.add_intel(
                        "media", f"reverse_img_{fname}",
                        saucenao_results, source="saucenao",
                    )
                    emit("finding", {
                        "type": "reverse_image",
                        "file": fname,
                        "domains": saucenao_results,
                        "provider": "saucenao",
                    })
                    print(f"  SauceNAO match domains: {saucenao_results}")

                if not saucenao_results and tineye_key:
                    try:
                        tineye_results = reverse_image_search_tineye(
                            fpath, api_key=tineye_key,
                        )
                    except Exception as exc:
                        log_trace(f"MediaStage: tineye raised "
                                  f"{type(exc).__name__}: {exc}")
                        tineye_results = []

                    if tineye_results:
                        ctx.intel_core.add_intel(
                            "media", f"reverse_img_tineye_{fname}",
                            tineye_results, source="tineye",
                        )
                        emit("finding", {
                            "type": "reverse_image",
                            "file": fname,
                            "domains": tineye_results,
                            "provider": "tineye",
                        })
                        print(f"  TinEye match domains: {tineye_results}")

        print(f"  Media stage complete. {len(avatar_files)} image(s) processed.")