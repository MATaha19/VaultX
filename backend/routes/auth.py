import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
)

from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from pydantic import BaseModel, EmailStr
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import User
from security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


# =========================================================
# ROUTER
# =========================================================

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


# =========================================================
# SECURITY CONFIGURATION
# =========================================================

MAX_FAILED_ATTEMPTS = 5

security = HTTPBearer(
    auto_error=True,
)


# =========================================================
# CURRENT USER
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(
        security
    ),
    db: Session = Depends(get_db),
):
    """
    Validate the JWT bearer token and return
    the authenticated VaultX user.
    """

    token = credentials.credentials

    try:
        payload = decode_access_token(token)

        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token",
            )

        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token",
            )

        user = (
            db.query(User)
            .filter(User.id == user_id)
            .first()
        )

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found",
            )

        if user.is_locked:
            raise HTTPException(
                status_code=403,
                detail="Account is locked",
            )

        return user

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired authentication token",
        )


# =========================================================
# REQUEST MODEL
# =========================================================

class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


# =========================================================
# RSA-2048 KEY GENERATION
# =========================================================

def generate_rsa_key_pair():
    """
    Generate an RSA-2048 public/private key pair.

    Both keys are stored as Base64-encoded PEM strings.
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_b64 = base64.b64encode(
        private_pem
    ).decode("utf-8")

    public_key_b64 = base64.b64encode(
        public_pem
    ).decode("utf-8")

    return public_key_b64, private_key_b64


# =========================================================
# REGISTER
# =========================================================

@router.post("/register")
def register(
    request: RegisterRequest,
    db: Session = Depends(get_db),
):
    username = request.username.strip()
    email = str(request.email).strip().lower()

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not username:
        raise HTTPException(
            status_code=400,
            detail="Username cannot be empty",
        )

    if len(username) < 3:
        raise HTTPException(
            status_code=400,
            detail="Username must be at least 3 characters",
        )

    if len(username) > 50:
        raise HTTPException(
            status_code=400,
            detail="Username cannot exceed 50 characters",
        )

    if len(request.password) < 6:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 6 characters",
        )

    # -----------------------------------------------------
    # USERNAME CHECK
    # -----------------------------------------------------

    existing_username = (
        db.query(User)
        .filter(func.lower(User.username) == func.lower(username))
        .first()
    )

    if existing_username:
        raise HTTPException(
            status_code=400,
            detail="Username already exists",
        )

    # -----------------------------------------------------
    # EMAIL CHECK
    # -----------------------------------------------------

    existing_email = (
        db.query(User)
        .filter(User.email == email)
        .first()
    )

    if existing_email:
        raise HTTPException(
            status_code=400,
            detail="Email already exists",
        )

    # -----------------------------------------------------
    # PASSWORD HASH
    # -----------------------------------------------------

    hashed_password = hash_password(
        request.password
    )

    # -----------------------------------------------------
    # RSA KEY PAIR
    # -----------------------------------------------------

    public_key, private_key = (
        generate_rsa_key_pair()
    )

    # -----------------------------------------------------
    # CREATE USER
    # -----------------------------------------------------

    user = User(
        username=username,
        email=email,
        password_hash=hashed_password,
        public_key=public_key,
        private_key=private_key,
        failed_login_attempts=0,
        is_locked=False,
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Failed to create account",
        )

    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    return {
        "message": "Account created successfully",
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
    }


# =========================================================
# CHECK USERNAME AVAILABILITY
# =========================================================

@router.get("/check-username/{username}")
def check_username_availability(
    username: str,
    db: Session = Depends(get_db),
):
    """
    Check whether a username is available.
    Used by the registration form for live duplicate checking.
    Case-insensitive, matching the check performed at registration.
    """

    username = username.strip()

    if not username:
        return {
            "available": False,
            "reason": "Username cannot be empty",
        }

    if len(username) < 3:
        return {
            "available": False,
            "reason": "Username must be at least 3 characters",
        }

    if len(username) > 50:
        return {
            "available": False,
            "reason": "Username cannot exceed 50 characters",
        }

    existing_username = (
        db.query(User)
        .filter(func.lower(User.username) == func.lower(username))
        .first()
    )

    if existing_username:
        return {
            "available": False,
            "reason": "Username already exists",
        }

    return {
        "available": True,
        "reason": None,
    }


# =========================================================
# LOGIN
# =========================================================

@router.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    Authenticate the user and generate a JWT access token.
    """

    username = username.strip()

    # -----------------------------------------------------
    # INPUT VALIDATION
    # -----------------------------------------------------

    if not username:
        raise HTTPException(
            status_code=400,
            detail="Username cannot be empty",
        )

    if not password:
        raise HTTPException(
            status_code=400,
            detail="Password cannot be empty",
        )

    # -----------------------------------------------------
    # FIND USER
    # -----------------------------------------------------

    user = (
        db.query(User)
        .filter(func.lower(User.username) == func.lower(username))
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    # -----------------------------------------------------
    # ACCOUNT LOCK CHECK
    # -----------------------------------------------------

    if user.is_locked:
        raise HTTPException(
            status_code=403,
            detail=(
                "Account is locked due to repeated "
                "failed login attempts"
            ),
        )

    # -----------------------------------------------------
    # PASSWORD VERIFICATION
    # -----------------------------------------------------

    password_valid = verify_password(
        password,
        user.password_hash,
    )

    if not password_valid:

        user.failed_login_attempts = (
            user.failed_login_attempts + 1
        )

        # -------------------------------------------------
        # LOCK ACCOUNT
        # -------------------------------------------------

        if (
            user.failed_login_attempts
            >= MAX_FAILED_ATTEMPTS
        ):
            user.is_locked = True

            db.commit()

            raise HTTPException(
                status_code=403,
                detail=(
                    "Account locked due to repeated "
                    "failed login attempts"
                ),
            )

        db.commit()

        remaining = (
            MAX_FAILED_ATTEMPTS
            - user.failed_login_attempts
        )

        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid username or password. "
                f"{remaining} attempt(s) remaining."
            ),
        )

    # -----------------------------------------------------
    # SUCCESSFUL LOGIN
    # -----------------------------------------------------

    user.failed_login_attempts = 0
    user.is_locked = False

    db.commit()

    # -----------------------------------------------------
    # CREATE JWT
    # -----------------------------------------------------

    access_token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "user_id": user.id,
    }


# =========================================================
# CURRENT USER
# =========================================================

@router.get("/me")
def get_me(
    current_user: User = Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "failed_login_attempts": (
            current_user.failed_login_attempts
        ),
        "is_locked": current_user.is_locked,
        "created_at": current_user.created_at,
    }


# =========================================================
# GET USER PUBLIC KEY
# =========================================================

@router.get("/user/{username}/public-key")
def get_user_public_key(
    username: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    username = username.strip()

    if not username:
        raise HTTPException(
            status_code=400,
            detail="Username cannot be empty",
        )

    user = (
        db.query(User)
        .filter(User.username == username)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    if not user.public_key:
        raise HTTPException(
            status_code=404,
            detail="RSA public key not found",
        )

    return {
        "username": user.username,
        "public_key": user.public_key,
    }