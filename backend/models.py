import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    role = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    weaver_profile = relationship("Weaver", back_populates="user", uselist=False)

class Weaver(Base):
    __tablename__ = "weavers"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    name_encrypted = Column(String, nullable=False)
    phone_encrypted = Column(String, nullable=True)
    address_encrypted = Column(String, nullable=True)
    voice_transcript_encrypted = Column(String, nullable=True)
    cluster = Column(String, nullable=False, default="Bargarh")
    village = Column(String, nullable=True, default="Barpali")
    experience_years = Column(Integer, default=15)
    lineage = Column(String, default="3rd-generation artisan")
    public_story = Column(Text, nullable=True)
    id_verified = Column(Boolean, default=False)
    id_type = Column(String, nullable=True)
    verified_by = Column(String, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    user = relationship("User", back_populates="weaver_profile")
    sarees = relationship("Saree", back_populates="weaver")
    consents = relationship("Consent", back_populates="weaver")

class Saree(Base):
    __tablename__ = "sarees"
    id = Column(String, primary_key=True, index=True)
    weaver_id = Column(String, ForeignKey("weavers.id"), nullable=False)
    title = Column(String, nullable=False)
    cluster = Column(String, nullable=False)
    origin = Column(String, nullable=False)
    gi_tag = Column(String, nullable=False)
    material = Column(String, nullable=False)
    loom_hours = Column(Integer, nullable=False)
    ties = Column(String, default="4,800")
    artisan_share = Column(String, default="80.0%")
    image_encrypted_path = Column(String, nullable=True)
    image_public_url = Column(Text, nullable=True)
    story = Column(Text, nullable=True)
    steps = Column(JSON, default=list)
    motifs = Column(JSON, default=list)
    care = Column(JSON, default=list)
    weave_fingerprint = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    weaver = relationship("Weaver", back_populates="sarees")
    tags = relationship("Tag", back_populates="saree")

class Tag(Base):
    __tablename__ = "tags"
    id = Column(String, primary_key=True, index=True)
    saree_id = Column(String, ForeignKey("sarees.id"), nullable=False)
    serial = Column(String, index=True, nullable=False)
    auth_code = Column(String, nullable=False)
    server_signature = Column(String, nullable=False)
    issued_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    renewal_count = Column(Integer, default=0)
    last_renewed_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    saree = relationship("Saree", back_populates="tags")
    scans = relationship("Scan", back_populates="tag")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, autoincrement=True)
    tag_id = Column(String, ForeignKey("tags.id"), nullable=False)
    serial = Column(String, index=True, nullable=False)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    is_fraud_flagged = Column(Boolean, default=False)
    fraud_reason = Column(String, nullable=True)
    detection_latency_ms = Column(Float, default=0.0)
    buyer_fee_simulated = Column(Float, default=200.0)
    tag = relationship("Tag", back_populates="scans")

class Order(Base):
    __tablename__ = "orders"
    id = Column(String, primary_key=True, index=True)
    saree_id = Column(String, ForeignKey("sarees.id"), nullable=True)
    weaver_id = Column(String, ForeignKey("weavers.id"), nullable=False)
    buyer_identifier = Column(String, nullable=True)
    craft_type = Column(String, nullable=False)
    brief = Column(Text, nullable=False)
    status = Column(String, default="Escrow_Initialized")
    escrow_amount = Column(Float, default=0.0)
    quote_amount = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class DesignUpload(Base):
    __tablename__ = "design_uploads"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    weaver_id = Column(String, ForeignKey("weavers.id"), nullable=True)
    title = Column(String, nullable=False)
    brief = Column(Text, nullable=False)
    encrypted_file_path = Column(String, nullable=False)
    file_mime_type = Column(String, nullable=False)
    file_size_kb = Column(Float, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Consent(Base):
    __tablename__ = "consents"
    id = Column(Integer, primary_key=True, autoincrement=True)
    weaver_id = Column(String, ForeignKey("weavers.id"), nullable=False)
    language = Column(String, default="or")
    purpose = Column(String, nullable=False)
    agreed = Column(Boolean, default=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    consent_hash = Column(String, nullable=False)
    weaver = relationship("Weaver", back_populates="consents")

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String, nullable=False)
    details = Column(Text, nullable=False)
    actor_id = Column(String, nullable=True)
    actor_role = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    latency_seconds = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class DeletionRequest(Base):
    __tablename__ = "deletion_requests"
    id = Column(String, primary_key=True, index=True)
    weaver_id = Column(String, ForeignKey("weavers.id"), nullable=False)
    requested_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String, default="Pending_Admin_Review")
    processed_at = Column(DateTime, nullable=True)
    processed_by = Column(String, nullable=True)
    reason = Column(Text, nullable=True)
