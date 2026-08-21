from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
)

from database import Base


# =========================================================
# USER MODEL
# =========================================================

class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    username = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    email = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    password_hash = Column(
        String,
        nullable=False,
    )

    # =====================================================
    # RSA-2048 KEY PAIR
    # =====================================================

    public_key = Column(
        String,
        nullable=True,
    )

    private_key = Column(
        String,
        nullable=True,
    )

    # =====================================================
    # FAILED LOGIN PROTECTION
    # =====================================================

    failed_login_attempts = Column(
        Integer,
        default=0,
        nullable=False,
    )

    is_locked = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    # =====================================================
    # TIMESTAMP
    # =====================================================

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )


# =========================================================
# FILE TRANSFER MODEL
# =========================================================

class FileTransfer(Base):
    __tablename__ = "file_transfers"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # =====================================================
    # SENDER
    # =====================================================

    sender_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    # =====================================================
    # RECIPIENT
    # =====================================================

    recipient_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    # =====================================================
    # ORIGINAL FILE INFORMATION
    # =====================================================

    original_filename = Column(
        String,
        nullable=False,
    )

    file_size = Column(
        Integer,
        nullable=False,
    )

    # =====================================================
    # ENCRYPTED FILE
    # =====================================================

    encrypted_filename = Column(
        String,
        nullable=False,
        unique=True,
    )

    # =====================================================
    # INTEGRITY
    # =====================================================

    sha256_hash = Column(
        String,
        nullable=False,
    )

    # =====================================================
    # AES-256-GCM PARAMETERS
    # =====================================================

    nonce = Column(
        String,
        nullable=False,
    )

    # AES key encrypted using recipient's RSA public key
    encrypted_aes_key = Column(
        String,
        nullable=False,
    )

    # =====================================================
    # TIMESTAMPS
    # =====================================================

    uploaded_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    expires_at = Column(
        DateTime,
        nullable=True,
    )

    # =====================================================
    # FILE STATUS
    # =====================================================

    is_deleted = Column(
        Boolean,
        default=False,
        nullable=False,
    )