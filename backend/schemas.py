from pydantic import BaseModel
from typing import List, Optional, Any, Dict

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    weaver_id: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class WeaverVoiceIntakeRequest(BaseModel):
    odia_transcript: str
    raw_audio_base64: Optional[str] = None
    language: Optional[str] = "or-IN"

class WeaverRegisterRequest(BaseModel):
    name: str
    pin: str
    phone: Optional[str] = None
    cluster: str = "Bargarh"
    village: str = "Barpali"
    experience_years: int = 15
    lineage: Optional[str] = "3rd-generation Bandha master"
    id_type: str = "Weaver ID Card"
    verified_by: Optional[str] = "Boyanika Regional Cluster Officer"
    dpdp_consent: bool = True
    voice_transcript: Optional[str] = None

class WeaverLoginRequest(BaseModel):
    name: str
    pin: str

class SareeCreateRequest(BaseModel):
    title: str
    cluster: str
    origin: str
    gi_tag: Optional[str] = "Registered Artisan Piece"
    loom_hours: int
    ties: Optional[str] = "4,500"
    material: str
    artisan_share: Optional[str] = "80.0%"
    motif_name: Optional[str] = "Pasapali Chessboard"
    story: Optional[str] = None
    image_base64: Optional[str] = None
    image_url: Optional[str] = None
    steps: Optional[List[Any]] = None
    motifs: Optional[List[Any]] = None
    care: Optional[List[str]] = None

class SareeVerifyRequest(BaseModel):
    serial: str
    code: Optional[str] = None
    qr_payload: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

class TagRenewalRequest(BaseModel):
    serial: str

class BespokeOrderRequest(BaseModel):
    weaver_id: str
    craft_type: str
    brief: str
    buyer_name: Optional[str] = "Artisan Supporter"

class PatronTipRequest(BaseModel):
    serial: str
    amount: float

class PatronNoteRequest(BaseModel):
    serial: str
    message: str

class OfflineSyncPayload(BaseModel):
    cached_scans: List[Dict[str, Any]] = []
    pending_registrations: List[Dict[str, Any]] = []

class DeletionSubmitRequest(BaseModel):
    reason: Optional[str] = "Weaver requested full profile erasure under DPDP Act 2023"
