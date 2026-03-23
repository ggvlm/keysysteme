import os
from dotenv import load_dotenv

load_dotenv()

ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "admin123")
SECRET_KEY: str = os.getenv("SECRET_KEY", "fallback-secret-key")
LINKVERTISE_URL: str = os.getenv("LINKVERTISE_URL", "https://linkvertise.com/YOUR_ID/YOUR_LINK")

# Token expiration in seconds (10 minutes)
TOKEN_MAX_AGE: int = 600
