from fastapi import FastAPI

from database import Base, engine
from routes.auth import router as auth_router
from routes.files import router as files_router


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="VaultX",
    description="Secure End-to-End File Transfer System",
    version="1.0.0",
)


# Register authentication routes
app.include_router(auth_router)

# Register file transfer routes
app.include_router(files_router)


@app.get("/")
def root():
    return {
        "message": "VaultX API is running",
        "status": "online",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
    }