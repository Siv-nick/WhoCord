"""
discord_osint/pipeline/stages/image_analysis.py
-------------------------------------------------
ImageAnalysisStage – Phase 4 image analysis module.

Reads from ctx
--------------
ctx.manual_image_url  – direct image URL to analyse

Writes to ctx
-------------
ctx.intel_core        – EXIF metadata, GPS coords, perceptual hash,
                        reverse-image search results, OCR text
ctx.avatar_urls       – the target image (for consistent rendering)
"""

from __future__ import annotations

import io
import os

from ..base import Stage, EmitFn
from ..context import InvestigationContext
from ...utils import CACHE_DIR
from ...extras import download_avatar, extract_metadata, reverse_image_search


class ImageAnalysisStage(Stage):
    name = "image_analysis"

    def run(self, ctx: InvestigationContext, emit: EmitFn = lambda *_: None) -> None:
        image_url = ctx.manual_image_url.strip()

        if not image_url or not image_url.startswith("http"):
            print("  [ImageAnalysis] No valid image URL supplied – skipping.")
            return

        print(f"\n{'=' * 60}")
        print(f"== Image Analysis: {image_url[:80]}")
        print(f"{'=' * 60}")
        emit("progress", {"message": f"Image analysis: {image_url[:60]}"})

        ctx.intel_core.add_intel("target", "image_url", image_url, source="manual_input")
        ctx.add_avatar(image_url)

        # ------------------------------------------------------------------ #
        # Download                                                             #
        # ------------------------------------------------------------------ #
        print("\n-- Downloading image --")
        emit("progress", {"message": "Downloading image"})
        avatar_dir = os.path.join(CACHE_DIR, "avatars")
        os.makedirs(avatar_dir, exist_ok=True)
        fpath = download_avatar(image_url, avatar_dir)

        if not fpath:
            print(f"  Download failed for {image_url}")
            return

        print(f"  Saved to: {fpath}")
        emit("finding", {"type": "avatar_downloaded", "path": fpath})

        # ------------------------------------------------------------------ #
        # EXIF metadata                                                        #
        # ------------------------------------------------------------------ #
        print("\n-- EXIF extraction --")
        emit("progress", {"message": "Extracting EXIF metadata"})
        fname = os.path.basename(fpath)
        try:
            meta = extract_metadata(fpath) or {}
            if meta:
                ctx.intel_core.add_intel("media", f"exif_{fname}", meta, source="exif")
                emit("finding", {"type": "exif_metadata", "file": fname, "data": meta})

                gps = meta.get("gps")
                if gps:
                    ctx.intel_core.add_intel("media", f"exif_gps_{fname}", gps, source="exif")
                    emit("finding", {"type": "exif_gps", "file": fname, "value": gps})
                    print(f"  GPS: {gps}")

                date_taken = meta.get("date_taken")
                if date_taken:
                    print(f"  Date taken: {date_taken}")

                camera = meta.get("camera")
                if camera:
                    print(f"  Camera: {camera}")
            else:
                print("  No EXIF data found.")
        except Exception as exc:
            print(f"  EXIF error: {exc}")

        # ------------------------------------------------------------------ #
        # Perceptual hash                                                      #
        # ------------------------------------------------------------------ #
        print("\n-- Perceptual hash --")
        emit("progress", {"message": "Computing perceptual hash"})
        phash = self._compute_phash(fpath)
        if phash:
            ctx.intel_core.add_intel("media", f"phash_{fname}", phash, source="imagehash")
            emit("finding", {"type": "perceptual_hash", "file": fname, "value": phash})
            print(f"  pHash: {phash}")

        # ------------------------------------------------------------------ #
        # Reverse image search                                                 #
        # ------------------------------------------------------------------ #
        cfg = ctx.config
        if cfg.ENABLE_REVERSE_IMG:
            print("\n-- Reverse image search --")
            emit("progress", {"message": "Reverse image search", "tool": "saucenao"})
            try:
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
                    print(f"  Reverse image: {results}")
                else:
                    print("  No reverse image matches.")
            except Exception as exc:
                print(f"  Reverse image error: {exc}")

        # ------------------------------------------------------------------ #
        # OCR (optional, tesseract-based)                                     #
        # ------------------------------------------------------------------ #
        ocr_text = self._run_ocr(fpath)
        if ocr_text:
            ctx.intel_core.add_intel("media", f"ocr_{fname}", ocr_text[:2000], source="tesseract")
            emit("finding", {"type": "ocr_text", "file": fname, "preview": ocr_text[:100]})
            print(f"  OCR text extracted ({len(ocr_text)} chars).")

        # ------------------------------------------------------------------ #
        # Image metadata (dimensions, format, mode)                           #
        # ------------------------------------------------------------------ #
        img_info = self._get_image_info(fpath)
        if img_info:
            ctx.intel_core.add_intel("media", f"info_{fname}", img_info, source="pillow")
            emit("finding", {"type": "image_info", "file": fname, "data": img_info})
            print(f"  Dimensions: {img_info.get('width')}×{img_info.get('height')}, "
                  f"Format: {img_info.get('format')}")

        print(f"\n== Image analysis complete ==")

    # ------------------------------------------------------------------ #
    # Private helpers                                                       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _compute_phash(fpath: str) -> str:
        try:
            import imagehash  # type: ignore
            from PIL import Image
            img = Image.open(fpath).convert("RGB")
            return str(imagehash.phash(img))
        except ImportError:
            return ""
        except Exception as exc:
            print(f"  pHash error: {exc}")
            return ""

    @staticmethod
    def _run_ocr(fpath: str) -> str:
        try:
            import pytesseract  # type: ignore
            from PIL import Image
            img = Image.open(fpath)
            return pytesseract.image_to_string(img).strip()
        except ImportError:
            return ""
        except Exception:
            return ""

    @staticmethod
    def _get_image_info(fpath: str) -> dict:
        try:
            from PIL import Image
            with Image.open(fpath) as img:
                return {
                    "width":  img.width,
                    "height": img.height,
                    "format": img.format or "unknown",
                    "mode":   img.mode,
                }
        except Exception:
            return {}
