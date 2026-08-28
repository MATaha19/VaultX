from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import Base, engine, SessionLocal
from routes.auth import router as auth_router
from routes.files import (
    router as files_router,
    cleanup_expired_files,
)


# =========================================================
# STARTUP / SHUTDOWN
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    # Create database tables if they do not exist
    Base.metadata.create_all(
        bind=engine
    )

    # Remove expired files
    db = SessionLocal()

    try:

        cleanup_expired_files(db)

    except Exception as exc:

        print(
            f"Startup cleanup warning: {exc}"
        )

    finally:

        db.close()

    print(
        "VaultX API started successfully."
    )

    yield

    print(
        "VaultX API shutting down."
    )


# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="VaultX",
    description=(
        "Secure End-to-End File Transfer System"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173",
        "https://beautiful-valkyrie-2a7bed.netlify.app",
    ],

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

    # -----------------------------------------------------
    # IMPORTANT:
    # Allows the React frontend to read custom
    # performance/security headers returned by FastAPI.
    # -----------------------------------------------------

    expose_headers=[
        "X-VaultX-Decryption-Time-Ms",
        "X-VaultX-File-Size",
        "X-VaultX-Encryption",
        "X-VaultX-Key-Protection",
        "X-VaultX-Integrity",
        "X-VaultX-Integrity-Verified",
    ],
)


# =========================================================
# API ROUTES
# =========================================================

app.include_router(
    auth_router
)

app.include_router(
    files_router
)


# =========================================================
# BASIC ROUTES
# =========================================================

@app.get("/")
def root():

    return {
        "message": (
            "VaultX API is running"
        ),
        "status": "online",
        "version": "1.0.0",
    }


@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": "VaultX API",
    }