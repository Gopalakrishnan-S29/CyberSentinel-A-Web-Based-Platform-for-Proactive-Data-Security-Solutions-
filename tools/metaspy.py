# tools/metaspy.py
import os
import time
import mimetypes
from typing import Dict, Any
from datetime import datetime

import exifread           # pip install exifread
from PIL import Image     # pip install Pillow
import PyPDF2             # pip install PyPDF2
import docx               # pip install python-docx


class MetaSpyScanner:
    """
    File metadata extractor.
    analyze_file(path) -> dict with metadata fields.
    Supports: JPEG/JPG/TIFF/PNG (EXIF), PDF (PyPDF2), DOCX (python-docx).
    """

    def __init__(self):
        pass

    def analyze_file(self, path: str) -> Dict[str, Any]:
        path = os.path.abspath(path)
        out: Dict[str, Any] = {
            "filename": os.path.basename(path),
            "path": path,
            "file_size": None,
            "mime": None,
            "fs_created": None,
            "fs_modified": None,
            "type": "other",
            "metadata": {},
        }

        if not os.path.exists(path):
            out["error"] = "file_not_found"
            return out

        try:
            st = os.stat(path)
            out["file_size"] = st.st_size
            out["fs_modified"] = datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
            out["fs_created"] = datetime.utcfromtimestamp(st.st_ctime).isoformat() + "Z"
        except Exception as e:
            out["metadata"]["fs_error"] = str(e)

        mime, _ = mimetypes.guess_type(path)
        out["mime"] = mime or "application/octet-stream"
        ext = os.path.splitext(path)[1].lower()

        if ext in (".jpg", ".jpeg", ".tiff", ".tif", ".png", ".heic"):
            out["type"] = "image"
            try:
                meta = self._extract_image_exif(path)
                out["metadata"].update(meta)
            except Exception as e:
                out["metadata"]["error"] = f"exif_error: {e}"

        elif ext == ".pdf":
            out["type"] = "pdf"
            try:
                meta = self._extract_pdf_metadata(path)
                out["metadata"].update(meta)
            except Exception as e:
                out["metadata"]["error"] = f"pdf_error: {e}"

        elif ext in (".docx",):
            out["type"] = "docx"
            try:
                meta = self._extract_docx_coreprops(path)
                out["metadata"].update(meta)
            except Exception as e:
                out["metadata"]["error"] = f"docx_error: {e}"
        else:
            if out["mime"] and out["mime"].startswith("image/"):
                out["type"] = "image"
                try:
                    meta = self._extract_image_exif(path)
                    out["metadata"].update(meta)
                except Exception:
                    pass

        return out

    def _extract_image_exif(self, path: str) -> Dict[str, Any]:
        meta = {}
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
        for k, v in tags.items():
            try:
                meta[str(k)] = str(v)
            except Exception:
                meta[str(k)] = repr(v)

        for tag in ("EXIF DateTimeOriginal", "Image DateTime", "EXIF DateTimeDigitized"):
            if tag in tags:
                meta["datetime"] = str(tags[tag])
                break

        if "Image Model" in tags:
            meta["camera_model"] = str(tags["Image Model"])
        if "Image Make" in tags:
            meta["camera_make"] = str(tags["Image Make"])

        gps_keys = [k for k in tags.keys() if k.startswith("GPS")]
        if gps_keys:
            meta["gps_raw"] = {k: str(tags[k]) for k in gps_keys}
            try:
                lat = self._exif_gps_to_decimal(tags, "GPS GPSLatitude", "GPS GPSLatitudeRef")
                lon = self._exif_gps_to_decimal(tags, "GPS GPSLongitude", "GPS GPSLongitudeRef")
                if lat is not None and lon is not None:
                    meta["gps_lat"] = lat
                    meta["gps_lon"] = lon
            except Exception:
                pass

        return meta

    def _exif_gps_to_decimal(self, tags, coord_tag, ref_tag):
        if coord_tag not in tags or ref_tag not in tags:
            return None
        try:
            coord = tags[coord_tag].values
            def _to_float(r):
                return float(r.num) / float(r.den) if getattr(r, "den", 1) else float(r)
            d = _to_float(coord[0])
            m = _to_float(coord[1])
            s = _to_float(coord[2]) if len(coord) >= 3 else 0.0
            deg = d + (m / 60.0) + (s / 3600.0)
            ref = str(tags[ref_tag])
            if ref in ("S", "W"):
                deg = -deg
            return round(deg, 6)
        except Exception:
            return None

    def _extract_pdf_metadata(self, path: str) -> Dict[str, Any]:
        meta = {}
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            info = reader.metadata
            if info:
                for k, v in info.items():
                    key = k.strip("/") if isinstance(k, str) else str(k)
                    meta[key] = str(v)
        return meta

    def _extract_docx_coreprops(self, path: str) -> Dict[str, Any]:
        meta = {}
        doc = docx.Document(path)
        props = doc.core_properties
        meta["author"] = props.author
        meta["title"] = props.title
        meta["subject"] = props.subject
        if props.created:
            try:
                meta["created"] = props.created.isoformat()
            except Exception:
                meta["created"] = str(props.created)
        if props.modified:
            try:
                meta["modified"] = props.modified.isoformat()
            except Exception:
                meta["modified"] = str(props.modified)
        meta["last_modified_by"] = props.last_modified_by
        meta["category"] = props.category
        meta["comments"] = props.comments
        return meta
