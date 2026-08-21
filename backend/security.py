import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from jose import JWTError, jwt
from pwdlib import PasswordHash


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()


# =========================================================
# PASSWORD HASHING
# =========================================================

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    try:
        return password_hash.verify(
            password,
            hashed_password,
        )
    except Exception:
        return False


# =========================================================
# JWT CONFIGURATION
# =========================================================

SECRET_KEY = os.getenv("SECRET_KEY")

ALGORITHM = os.getenv(
    "ALGORITHM",
    "HS256",
)

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv(
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "60",
    )
)


if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not configured. "
        "Create a .env file in the backend directory."
    )


# =========================================================
# JWT CREATION
# =========================================================

def create_access_token(
    user_id: int,
    username: str,
) -> str:

    expire = (
        datetime.now(timezone.utc)
        + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES,
        )
    )

    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


# =========================================================
# JWT VALIDATION
# =========================================================

def decode_access_token(
    token: str,
) -> dict:

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id = payload.get("sub")

        if not user_id:
            raise ValueError(
                "Invalid token payload"
            )

        return payload

    except JWTError as exc:
        raise ValueError(
            "Invalid or expired token"
        ) from exc