import base64
import hashlib
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from fastapi.responses import Response
from sqlalchemy.orm import Session

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from database import get_db
from models import FileTransfer, User
from routes.auth import get_current_user


router = APIRouter(
    prefix="/files",
    tags=["Secure File Transfer"]
)


# =========================================================
# STORAGE
# =========================================================

STORAGE_DIR = (
    Path(__file__).resolve().parent.parent / "storage"
)

STORAGE_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# =========================================================
# RSA KEY HELPERS
# =========================================================

def decode_key(key_text: str) -> bytes:
    """
    Supports both:
    1. Normal PEM keys
    2. Base64-encoded PEM keys

    This keeps compatibility with existing VaultX users.
    """

    if not key_text:
        raise ValueError("RSA key is empty")

    key_text = key_text.strip()

    # Normal PEM key
    if "-----BEGIN" in key_text:
        return key_text.encode("utf-8")

    # Base64 encoded PEM key
    try:
        decoded = base64.b64decode(
            key_text,
            validate=True
        )

        if b"-----BEGIN" in decoded:
            return decoded

    except Exception:
        pass

    raise ValueError(
        "Unsupported RSA key format"
    )


def load_public_key(public_key_text: str):
    """
    Load RSA public key from either
    normal PEM or Base64-encoded PEM.
    """

    key_bytes = decode_key(
        public_key_text
    )

    return serialization.load_pem_public_key(
        key_bytes
    )


def load_private_key(private_key_text: str):
    """
    Load RSA private key from either
    normal PEM or Base64-encoded PEM.
    """

    key_bytes = decode_key(
        private_key_text
    )

    return serialization.load_pem_private_key(
        key_bytes,
        password=None
    )


# =========================================================
# SECURITY HELPERS
# =========================================================

def calculate_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# =========================================================
# EXPIRED FILE CLEANUP
# =========================================================

def cleanup_expired_files(db: Session):

    now = datetime.utcnow()

    expired_files = (
        db.query(FileTransfer)
        .filter(
            FileTransfer.expires_at.isnot(None),
            FileTransfer.expires_at <= now,
            FileTransfer.is_deleted == False
        )
        .all()
    )

    for transfer in expired_files:

        encrypted_path = (
            STORAGE_DIR /
            transfer.encrypted_filename
        )

        if encrypted_path.exists():

            try:
                encrypted_path.unlink()
            except OSError:
                pass

        transfer.is_deleted = True

    if expired_files:
        db.commit()


# =========================================================
# UPLOAD / SEND FILE
# =========================================================

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    recipient_username: str = Form(...),
    expiration_hours: int = Form(24),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    cleanup_expired_files(db)

    # -----------------------------------------------------
    # Validate expiration
    # -----------------------------------------------------

    if expiration_hours <= 0:
        raise HTTPException(
            status_code=400,
            detail="Expiration must be greater than zero"
        )

    if expiration_hours > 168:
        raise HTTPException(
            status_code=400,
            detail="Maximum expiration period is 7 days"
        )

    # -----------------------------------------------------
    # Prevent self transfer
    # -----------------------------------------------------

    if recipient_username == current_user.username:
        raise HTTPException(
            status_code=400,
            detail="You cannot send a file to yourself"
        )

    # -----------------------------------------------------
    # Find recipient
    # -----------------------------------------------------

    recipient = (
        db.query(User)
        .filter(
            User.username == recipient_username
        )
        .first()
    )

    if not recipient:

        raise HTTPException(
            status_code=404,
            detail="Recipient user not found"
        )

    # -----------------------------------------------------
    # Check public key
    # -----------------------------------------------------

    if not recipient.public_key:

        raise HTTPException(
            status_code=400,
            detail="Recipient does not have an RSA public key"
        )

    # -----------------------------------------------------
    # Read file
    # -----------------------------------------------------

    file_data = await file.read()

    if not file_data:

        raise HTTPException(
            status_code=400,
            detail="Cannot upload an empty file"
        )

    # -----------------------------------------------------
    # SHA-256
    # -----------------------------------------------------

    sha256_hash = calculate_sha256(
        file_data
    )

    # -----------------------------------------------------
    # AES-256-GCM (timed)
    # -----------------------------------------------------

    encryption_start = time.perf_counter()

    aes_key = AESGCM.generate_key(
        bit_length=256
    )

    nonce = os.urandom(12)

    aes = AESGCM(aes_key)

    encrypted_data = aes.encrypt(
        nonce,
        file_data,
        None
    )

    # -----------------------------------------------------
    # RSA PUBLIC KEY
    # -----------------------------------------------------

    try:

        recipient_public_key = load_public_key(
            recipient.public_key
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Invalid recipient RSA public key: {str(e)}"
        )

    # -----------------------------------------------------
    # RSA-2048 OAEP
    # -----------------------------------------------------

    try:

        encrypted_aes_key = (
            recipient_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(
                        algorithm=hashes.SHA256()
                    ),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        )

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Failed to protect encryption key"
        )

    encryption_time_ms = round(
        (time.perf_counter() - encryption_start) * 1000,
        3
    )

    # -----------------------------------------------------
    # Encrypted filename
    # -----------------------------------------------------

    encrypted_filename = (
        f"{uuid4().hex}.vaultx"
    )

    encrypted_path = (
        STORAGE_DIR /
        encrypted_filename
    )

    # -----------------------------------------------------
    # Save encrypted file
    # -----------------------------------------------------

    try:

        encrypted_path.write_bytes(
            encrypted_data
        )

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Failed to store encrypted file"
        )

    # -----------------------------------------------------
    # Expiration
    # -----------------------------------------------------

    expires_at = (
        datetime.utcnow()
        + timedelta(hours=expiration_hours)
    )

    # -----------------------------------------------------
    # Database
    # -----------------------------------------------------

    transfer = FileTransfer(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        original_filename=(
            file.filename or "unnamed_file"
        ),
        file_size=len(file_data),
        encrypted_filename=encrypted_filename,
        sha256_hash=sha256_hash,
        nonce=base64.b64encode(
            nonce
        ).decode("utf-8"),
        encrypted_aes_key=base64.b64encode(
            encrypted_aes_key
        ).decode("utf-8"),
        uploaded_at=datetime.utcnow(),
        expires_at=expires_at,
        is_deleted=False
    )

    db.add(transfer)
    db.commit()
    db.refresh(transfer)

    return {
        "message": "File encrypted and sent successfully",
        "file_id": transfer.id,
        "filename": transfer.original_filename,
        "sender": current_user.username,
        "recipient": recipient.username,
        "file_size": transfer.file_size,
        "sha256": transfer.sha256_hash,
        "expires_at": transfer.expires_at,
        "encryption": "AES-256-GCM",
        "key_protection": "RSA-2048",
        "integrity": "SHA-256",
        "encryption_time_ms": encryption_time_ms
    }


# =========================================================
# RECEIVED FILES
# =========================================================

@router.get("/my-files")
def get_received_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    cleanup_expired_files(db)

    files = (
        db.query(FileTransfer)
        .filter(
            FileTransfer.recipient_id == current_user.id,
            FileTransfer.is_deleted == False
        )
        .order_by(
            FileTransfer.uploaded_at.desc()
        )
        .all()
    )

    result = []

    for transfer in files:

        sender = (
            db.query(User)
            .filter(
                User.id == transfer.sender_id
            )
            .first()
        )

        result.append({
            "file_id": transfer.id,
            "filename": transfer.original_filename,
            "file_size": transfer.file_size,
            "sender": (
                sender.username
                if sender
                else "Unknown"
            ),
            "uploaded_at": transfer.uploaded_at,
            "expires_at": transfer.expires_at,
            "deleted": transfer.is_deleted
        })

    return {
        "files": result
    }


# =========================================================
# SENT FILES
# =========================================================

@router.get("/sent")
def get_sent_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    cleanup_expired_files(db)

    files = (
        db.query(FileTransfer)
        .filter(
            FileTransfer.sender_id == current_user.id,
            FileTransfer.is_deleted == False
        )
        .order_by(
            FileTransfer.uploaded_at.desc()
        )
        .all()
    )

    result = []

    for transfer in files:

        recipient = (
            db.query(User)
            .filter(
                User.id == transfer.recipient_id
            )
            .first()
        )

        result.append({
            "file_id": transfer.id,
            "filename": transfer.original_filename,
            "file_size": transfer.file_size,
            "recipient": (
                recipient.username
                if recipient
                else "Unknown"
            ),
            "uploaded_at": transfer.uploaded_at,
            "expires_at": transfer.expires_at,
            "deleted": transfer.is_deleted
        })

    return {
        "files": result
    }


# =========================================================
# SECURE DOWNLOAD
# =========================================================

@router.get("/{file_id}/download")
def download_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    cleanup_expired_files(db)

    # -----------------------------------------------------
    # Find transfer
    # -----------------------------------------------------

    transfer = (
        db.query(FileTransfer)
        .filter(
            FileTransfer.id == file_id,
            FileTransfer.is_deleted == False
        )
        .first()
    )

    if not transfer:

        raise HTTPException(
            status_code=404,
            detail="File not found or expired"
        )

    # -----------------------------------------------------
    # Recipient-only authorization
    # -----------------------------------------------------

    if transfer.recipient_id != current_user.id:

        raise HTTPException(
            status_code=403,
            detail="You are not authorized to download this file"
        )

    # -----------------------------------------------------
    # Expiration
    # -----------------------------------------------------

    if (
        transfer.expires_at
        and transfer.expires_at <= datetime.utcnow()
    ):

        cleanup_expired_files(db)

        raise HTTPException(
            status_code=410,
            detail="File has expired"
        )

    # -----------------------------------------------------
    # Private key
    # -----------------------------------------------------

    if not current_user.private_key:

        raise HTTPException(
            status_code=500,
            detail="Recipient private key is unavailable"
        )

    # -----------------------------------------------------
    # Encrypted file
    # -----------------------------------------------------

    encrypted_path = (
        STORAGE_DIR /
        transfer.encrypted_filename
    )

    if not encrypted_path.exists():

        raise HTTPException(
            status_code=404,
            detail="Encrypted file is missing"
        )

    try:

        # Read encrypted file
        encrypted_data = (
            encrypted_path.read_bytes()
        )

        # Decode nonce
        nonce = base64.b64decode(
            transfer.nonce
        )

        # Decode encrypted AES key
        encrypted_aes_key = (
            base64.b64decode(
                transfer.encrypted_aes_key
            )
        )

        # Load private key
        private_key = load_private_key(
            current_user.private_key
        )

        # Decryption timing starts here (RSA + AES steps only,
        # excludes disk reads and integrity check)
        decryption_start = time.perf_counter()

        # RSA decrypt AES key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(
                    algorithm=hashes.SHA256()
                ),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # AES decrypt
        aes = AESGCM(aes_key)

        decrypted_data = aes.decrypt(
            nonce,
            encrypted_data,
            None
        )

        decryption_time_ms = round(
            (time.perf_counter() - decryption_start) * 1000,
            3
        )

        # SHA-256 verification
        calculated_hash = calculate_sha256(
            decrypted_data
        )

        if calculated_hash != transfer.sha256_hash:

            raise HTTPException(
                status_code=500,
                detail="File integrity verification failed"
            )

    except HTTPException:
        raise

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="File decryption failed"
        )

    # -----------------------------------------------------
    # Return decrypted file
    # -----------------------------------------------------

    return Response(
        content=decrypted_data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{transfer.original_filename}"'
            ),
            "X-VaultX-Encryption": "AES-256-GCM",
            "X-VaultX-Key-Protection": "RSA-2048",
            "X-VaultX-Integrity": "SHA-256",
            "X-VaultX-Integrity-Verified": "true",
            "X-VaultX-Decryption-Time-Ms": str(decryption_time_ms)
        }
    )


# =========================================================
# REVOKE FILE
# =========================================================

@router.delete("/{file_id}")
def revoke_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    transfer = (
        db.query(FileTransfer)
        .filter(
            FileTransfer.id == file_id,
            FileTransfer.is_deleted == False
        )
        .first()
    )

    if not transfer:

        raise HTTPException(
            status_code=404,
            detail="File not found"
        )

    # Only sender
    if transfer.sender_id != current_user.id:

        raise HTTPException(
            status_code=403,
            detail="Only the sender can revoke this file"
        )

    encrypted_path = (
        STORAGE_DIR /
        transfer.encrypted_filename
    )

    if encrypted_path.exists():

        try:
            encrypted_path.unlink()
        except OSError:
            pass

    transfer.is_deleted = True

    db.commit()

    return {
        "message": "File transfer revoked successfully",
        "file_id": transfer.id
    }