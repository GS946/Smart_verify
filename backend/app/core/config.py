import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "AICTE SmartVerify AI"
    APP_VERSION: str = "1.0.0"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "aicte_smartverify_demo_secret_key_sih2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'aicte_smartverify.db'))}")

    # Storage & Security
    STORAGE_DIR: str = os.getenv("STORAGE_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "storage"))
    DATA_RETENTION_DAYS: int = int(os.getenv("DATA_RETENTION_DAYS", "180"))
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "uN_yE5V8W1mK_9pX2L4tQ6zB0dF7hJ3rA5cE8gI1kM=") # Demo Fernet Key

    # Regulatory Banner
    COMPLIANCE_BANNER: str = (
        "Decision-support system. Final approval/denial remains with competent AICTE authorities."
    )

    class Config:
        env_file = ".env"

settings = Settings()

os.makedirs(settings.STORAGE_DIR, exist_ok=True)
