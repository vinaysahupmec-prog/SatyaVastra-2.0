import os
import uuid
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, Weaver, Saree, Tag, Scan, AuditLog, Consent
from security import encrypt_field, hash_password, sign_qr_payload, compute_deterministic_code

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./satyavastra.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def seed_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    admin_user = User(
        id="USR-ADMIN-01",
        username="admin",
        role="admin",
        password_hash=hash_password("admin123")
    )
    db.add(admin_user)

    now = datetime.datetime.utcnow()
    expires_at = now + datetime.timedelta(days=120)

    weavers_seed = [
        ("WVR-0941", "Niranjan Meher", "niranjan_meher", "1234", "Bargarh", "Barpali", 32, "Weaver ID Card", "Odisha State Handloom Directorate", "OR-SMB-2026-9041", "Traditional Pasapali Silk Saree", "Sambalpuri Bandha (GI)", 112, "Pure Mulberry Silk", "/images/pasapali.jpg"),
        ("WVR-3829", "Hemalata Meher", "hemalata_meher", "2345", "Subarnapur", "Sonepur", 26, "Cooperative Attestation", "Subarnapur Primary Weavers Cooperative Society", "OR-SNP-2026-3829", "Royal Bomkai Sachipar Silk Saree", "Bomkai Handloom (GI)", 148, "Mulberry Silk & Zari", "/images/bomkai.jpg"),
        ("WVR-1184", "Damodar Mirgan", "damodar_mirgan", "3456", "Koraput", "Kotpad", 40, "Weaver ID Card", "Koraput Integrated Tribal Development Agency", "OR-KTP-2026-1184", "Kotpad Aal-Dyed Organic Tribal Weave", "Kotpad Handloom (GI)", 180, "Handspun Organic Cotton", "/images/kotpad.jpg"),
        ("WVR-2207", "Sulochana Bhoi", "sulochana_bhoi", "4567", "Sambalpur", "Sambalpur", 29, "Cooperative Attestation", "Sambalpur Handloom Apex Society", "OR-SBP-2026-2207", "Sambalpuri Ikat Bandha Saree", "Sambalpuri Bandha (GI)", 126, "Mulberry Silk", "/images/sambalpuri.jpg")
    ]

    for wid, name, uname, pin, cluster, village, exp, id_t, attester, s_id, title, gi, hrs, mat, img in weavers_seed:
        u = User(id=f"USR-{wid}", username=uname, role="weaver", password_hash=hash_password(pin))
        db.add(u)
        w = Weaver(
            id=wid,
            user_id=u.id,
            name_encrypted=encrypt_field(name),
            phone_encrypted=encrypt_field("9437100000"),
            address_encrypted=encrypt_field(f"{village}, {cluster}, Odisha"),
            cluster=cluster,
            village=village,
            experience_years=exp,
            id_verified=True,
            id_type=id_t,
            verified_by=attester,
            verified_at=now
        )
        db.add(w)
        db.add(Consent(weaver_id=wid, language="or", purpose="GI Craft Passport", agreed=True, consent_hash=uuid.uuid4().hex))
        s = Saree(
            id=s_id,
            weaver_id=wid,
            title=title,
            cluster=cluster,
            origin=f"{village}, {cluster} cluster, Odisha",
            gi_tag=gi,
            material=mat,
            loom_hours=hrs,
            image_public_url=img,
            story=f"Handcrafted in {cluster} on traditional pit looms.",
            steps=[["Yarn preparation", 15], ["Tie-resist & dyeing", 35], ["Weaving", 50]],
            motifs=[["Traditional Motifs", "ନକ୍ସା", "Heritage pattern"]],
            care=["Dry-clean first wash", "Dry in partial shade"],
            weave_fingerprint=[0.05] * 16
        )
        db.add(s)
        auth_code = compute_deterministic_code(s_id, name, hrs)
        sig = sign_qr_payload(s_id, int(expires_at.timestamp()))
        t = Tag(
            id=f"TAG-{uuid.uuid4().hex[:6].upper()}",
            saree_id=s_id,
            serial=s_id,
            auth_code=auth_code,
            server_signature=sig,
            issued_at=now,
            expires_at=expires_at,
            is_active=True
        )
        db.add(t)
        db.add(Scan(tag_id=t.id, serial=s_id, scanned_at=now - datetime.timedelta(hours=1), ip_address="103.21.124.8", detection_latency_ms=18.4, buyer_fee_simulated=200.0))
        db.add(AuditLog(event_type="SYSTEM_BOOTSTRAP", details="SatyaVastra Trust Protocol initialized (FastAPI v1 Contract)", actor_id="SYSTEM", actor_role="admin"))

    db.commit()
    print("[SEED SUCCESS] Database populated with verified sample data.")

if __name__ == "__main__":
    seed_database()
