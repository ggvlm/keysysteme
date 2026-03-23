import hmac
from typing import Optional

from fastapi import Cookie, Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlmodel import Session, select

import config
from database import get_session, init_db
from models import Key

app = FastAPI(title="Key Distribution App")
templates = Jinja2Templates(directory="templates")

serializer = URLSafeTimedSerializer(config.SECRET_KEY)
ADMIN_COOKIE_NAME = "admin_session"
ADMIN_COOKIE_VALUE = "authenticated"


@app.on_event("startup")
def on_startup():
    init_db()


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def create_claim_token() -> str:
    return serializer.dumps("claim", salt="claim-salt")


def verify_claim_token(token: str) -> bool:
    try:
        serializer.loads(token, salt="claim-salt", max_age=config.TOKEN_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def is_admin(admin_session: Optional[str] = Cookie(default=None)) -> bool:
    return admin_session == ADMIN_COOKIE_VALUE


def require_admin(admin_session: Optional[str] = Cookie(default=None)):
    if admin_session != ADMIN_COOKIE_VALUE:
        raise HTTPException(status_code=status.HTTP_302_FOUND, headers={"Location": "/admin"})


# ──────────────────────────────────────────────
# USER ROUTES
# ──────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/go")
def go(session: Session = Depends(get_session)):
    """Create a signed token and redirect to Linkvertise with it as the ?after= callback."""
    token = create_claim_token()
    # The Linkvertise link embeds our /claim URL as the destination
    callback_url = f"http://localhost:8000/claim?token={token}"
    # Build destination — replace placeholder with real URL when deploying
    linkvertise_url = config.LINKVERTISE_URL
    # Append our callback; Linkvertise will redirect to it after completion
    redirect_url = f"{linkvertise_url}?r={callback_url}"
    return RedirectResponse(url=redirect_url, status_code=302)


@app.get("/claim", response_class=HTMLResponse)
def claim(request: Request, token: Optional[str] = None, session: Session = Depends(get_session)):
    """Verify the signed token, pop one unused key, and display it."""
    # No token → reject
    if not token or not verify_claim_token(token):
        return templates.TemplateResponse(
            "claim.html",
            {"request": request, "error": "Lien invalide ou expiré. Recommence depuis le début."},
            status_code=403,
        )

    # Fetch one unused key
    statement = select(Key).where(Key.is_used == False).limit(1)
    key = session.exec(statement).first()

    if key is None:
        return templates.TemplateResponse(
            "claim.html",
            {"request": request, "error": "Plus aucune clé disponible pour le moment. Reviens plus tard."},
            status_code=200,
        )

    # Mark as used
    key.is_used = True
    session.add(key)
    session.commit()

    return templates.TemplateResponse("claim.html", {"request": request, "key": key.value})


# ──────────────────────────────────────────────
# ADMIN ROUTES
# ──────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
def admin_login_page(request: Request, admin_session: Optional[str] = Cookie(default=None)):
    if admin_session == ADMIN_COOKIE_VALUE:
        return RedirectResponse(url="/admin/panel", status_code=302)
    return templates.TemplateResponse("admin_login.html", {"request": request})


@app.post("/admin/login")
def admin_login(password: str = Form(...)):
    if hmac.compare_digest(password.encode(), config.ADMIN_PASSWORD.encode()):
        response = RedirectResponse(url="/admin/panel", status_code=302)
        response.set_cookie(
            key=ADMIN_COOKIE_NAME,
            value=ADMIN_COOKIE_VALUE,
            httponly=True,
            max_age=3600,  # 1 hour
            samesite="lax",
        )
        return response
    raise HTTPException(status_code=401, detail="Mot de passe incorrect")


@app.get("/admin/panel", response_class=HTMLResponse)
def admin_panel(request: Request, admin_session: Optional[str] = Cookie(default=None), session: Session = Depends(get_session)):
    if admin_session != ADMIN_COOKIE_VALUE:
        return RedirectResponse(url="/admin", status_code=302)
    count = session.exec(select(Key).where(Key.is_used == False)).all()
    return templates.TemplateResponse("admin_panel.html", {"request": request, "remaining": len(count)})


@app.post("/admin/add-keys")
def admin_add_keys(
    keys_text: str = Form(...),
    admin_session: Optional[str] = Cookie(default=None),
    session: Session = Depends(get_session),
):
    if admin_session != ADMIN_COOKIE_VALUE:
        return RedirectResponse(url="/admin", status_code=302)

    lines = [line.strip() for line in keys_text.strip().splitlines() if line.strip()]
    added = 0
    skipped = 0
    for value in lines:
        # Skip duplicates
        existing = session.exec(select(Key).where(Key.value == value)).first()
        if existing:
            skipped += 1
            continue
        key = Key(value=value)
        session.add(key)
        added += 1
    session.commit()

    return RedirectResponse(
        url=f"/admin/panel?added={added}&skipped={skipped}",
        status_code=302,
    )


@app.get("/admin/stats")
def admin_stats(admin_session: Optional[str] = Cookie(default=None), session: Session = Depends(get_session)):
    if admin_session != ADMIN_COOKIE_VALUE:
        raise HTTPException(status_code=401)
    count = len(session.exec(select(Key).where(Key.is_used == False)).all())
    return JSONResponse({"remaining": count})


@app.get("/admin/logout")
def admin_logout():
    response = RedirectResponse(url="/admin", status_code=302)
    response.delete_cookie(ADMIN_COOKIE_NAME)
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
