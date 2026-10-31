import os
import io
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Tuple, List, Optional
from PIL import Image
import numpy as np

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

class WeaverVoiceProcessor:
    @staticmethod
    def process_speech(transcript_text: str) -> Dict[str, Any]:
        text = transcript_text.strip()
        extracted = {
            "cluster": "Bargarh",
            "village": "Barpali",
            "craft": "Sambalpuri Pasapali Bandha",
            "hours": 120,
            "ties": "4,800 ties",
            "material": "Pure Mulberry Silk",
            "motif": "Pasapali & Shankha",
            "years": 25,
            "story": text
        }
        if "ବୋମକାଇ" in text or "ସୁବର୍ଣ୍ଣପୁର" in text or "bomkai" in text.lower():
            extracted.update({
                "cluster": "Subarnapur",
                "village": "Sonepur",
                "craft": "Royal Bomkai Sachipar",
                "material": "Mulberry Silk & Zari",
                "motif": "Mayura (Peacock) & Padma",
                "hours": 148,
                "ties": "6,200 ties"
            })
        elif "କୋଟପାଡ଼" in text or "କୋରାପୁଟ" in text or "kotpad" in text.lower():
            extracted.update({
                "cluster": "Koraput",
                "village": "Kotpad",
                "craft": "Kotpad Aal-Dyed Organic Weave",
                "material": "Handspun Organic Cotton",
                "motif": "Machha (Fish) & Chauka",
                "hours": 180,
                "ties": "2,400 ties"
            })
        elif "ସମ୍ବଲପୁର" in text or "sambalpur" in text.lower():
            extracted.update({
                "cluster": "Sambalpur",
                "village": "Sambalpur",
                "craft": "Sambalpuri Ikat Bandha",
                "material": "Mulberry Silk",
                "motif": "Chakra & Phula",
                "hours": 126,
                "ties": "5,400 ties"
            })
        
        odia_digits = {
            '୦': '0', '୧': '1', '୨': '2', '୩': '3', '୪': '4',
            '୫': '5', '୬': '6', '୭': '7', '୮': '8', '୯': '9'
        }
        normalized = text
        for k, v in odia_digits.items():
            normalized = normalized.replace(k, v)

        for token in normalized.split():
            clean = "".join([c for c in token if c.isdigit()])
            if clean and 20 <= int(clean) <= 500:
                extracted["hours"] = int(clean)
        
        return extracted

class FraudDetectionEngine:
    @staticmethod
    def evaluate_scan(serial: str, recent_scans: List[Any], current_ip: str) -> Tuple[bool, Optional[str], float]:
        start = time.perf_counter()
        is_flagged = False
        reason = None
        now = datetime.utcnow()
        two_min_ago = now - timedelta(minutes=2)
        one_hour_ago = now - timedelta(hours=1)
        
        relevant = [s for s in recent_scans if s.serial == serial]
        if sum(1 for s in relevant if s.scanned_at >= two_min_ago) >= 3:
            is_flagged = True
            reason = "High velocity anomaly: Scan bursts indicate physical tag duplication"
            
        ips = {s.ip_address for s in relevant if s.scanned_at >= one_hour_ago and s.ip_address}
        ips.add(current_ip)
        if len(ips) >= 4:
            is_flagged = True
            reason = f"Distributed scan attack detected across {len(ips)} disparate networks"
            
        latency_seconds = time.perf_counter() - start
        return is_flagged, reason, latency_seconds

class MicroWeaveFeasibility:
    @staticmethod
    def extract_fingerprint(image_bytes: bytes) -> List[float]:
        try:
            img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((128, 128))
            arr = np.array(img, dtype=np.float32) / 255.0
            gx = np.diff(arr, axis=1)
            gy = np.diff(arr, axis=0)
            angles = np.arctan2(gy[:, :-1], gx[:-1, :])
            hist, _ = np.histogram(angles, bins=16, range=(-np.pi, np.pi), density=True)
            norm = np.linalg.norm(hist) + 1e-7
            return [round(float(x), 4) for x in (hist / norm).tolist()]
        except Exception:
            return [0.0] * 16

    @staticmethod
    def compare_fingerprints(vec_a: List[float], vec_b: List[float]) -> float:
        if not vec_a or not vec_b or len(vec_a) != len(vec_b):
            return 0.0
        va, vb = np.array(vec_a), np.array(vec_b)
        dot = np.dot(va, vb)
        norm = (np.linalg.norm(va) * np.linalg.norm(vb)) + 1e-7
        return round(float(np.clip(dot / norm, 0.0, 1.0)), 4)
