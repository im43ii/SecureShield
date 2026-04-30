from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import bcrypt
import jwt
import json
import os
import logging
from datetime import datetime, timedelta

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
SECRET_KEY = "secureshield-secret-key-2026"
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 2
DB_FILE = "users.json"
LOG_FILE = "security.log"

app = FastAPI(title="SecureShield RBAC API")
security = HTTPBearer()

# In-memory token blacklist
blacklist = set()

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

def log_unauthorized(action: str):
    logging.warning(f"UNAUTHORIZED ACCESS ATTEMPT | Action: {action}")

# ─────────────────────────────────────────────
# DATABASE (JSON FILE)
# ─────────────────────────────────────────────
def load_users():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(DB_FILE, "w") as f:
        json.dump(users, f, indent=4)

# ─────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────
class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str = "user"  # "user" or "admin"

class LoginRequest(BaseModel):
    username: str
    password: str

# ─────────────────────────────────────────────
# JWT HELPERS
# ─────────────────────────────────────────────
def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ─────────────────────────────────────────────
# AUTH MIDDLEWARE
# ─────────────────────────────────────────────
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if token in blacklist:
        raise HTTPException(status_code=401, detail="Token has been revoked")
    payload = decode_token(token)
    return {"username": payload["sub"], "role": payload["role"], "token": token}

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        log_unauthorized(f"User '{current_user['username']}' tried to access admin route")
        raise HTTPException(status_code=403, detail="Forbidden: Admins only")
    return current_user

# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

# Task 1 — Register with bcrypt
@app.post("/register")
def register(data: RegisterRequest):
    users = load_users()
    if data.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    hashed = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()
    users[data.username] = {"password": hashed, "role": data.role}
    save_users(users)
    return {"message": f"User '{data.username}' registered successfully"}

# Task 2 — Login and issue JWT
@app.post("/login")
def login(data: LoginRequest):
    users = load_users()
    if data.username not in users:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user = users[data.username]
    if not bcrypt.checkpw(data.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_token(data.username, user["role"])
    return {"access_token": token, "token_type": "bearer"}

# Task 4 — Profile (User + Admin)
@app.get("/profile")
def profile(current_user: dict = Depends(get_current_user)):
    return {
        "message": f"Welcome {current_user['username']}!",
        "role": current_user["role"]
    }

# Task 4 — Delete user (Admin only)
@app.delete("/user/{user_id}")
def delete_user(user_id: str, current_user: dict = Depends(require_admin)):
    users = load_users()
    if user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    del users[user_id]
    save_users(users)
    return {"message": f"User '{user_id}' deleted successfully"}

# Task 5 — Logout (blacklist token)
@app.post("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    blacklist.add(current_user["token"])
    return {"message": "Logged out successfully. Token has been revoked."}
