import hashlib
import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta

app = FastAPI()
users = []
messages = []

SECRET_KEY = "your_secret_key"  
ALGORITHM = "HS256"  
ACCESS_TOKEN_EXPIRE_MINUTES = 30 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def create_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_user(username: str):
    for user in users:
        if user["username"] == username:
            return user
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user(username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.on_event("startup")
def add_master_user():
    master_username = "admin"
    master_password = "secret"
    if not get_user(master_username):
        hashed_password = hash_password(master_password)
        users.append({"username": master_username, "password": hashed_password})

@app.post("/register")
def register(username: str, password: str):
    if get_user(username):
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = hash_password(password)
    users.append({"username": username, "password": hashed_password})
    return {"message": "User registered successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if user is None or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user["username"])
    return {"access_token": token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"username": current_user["username"]}

@app.post("/messages/send")
async def send_message(receiver: str, content: str, current_user: dict = Depends(get_current_user)):
    if not get_user(receiver):
        raise HTTPException(status_code=404, detail="Receiver not found")
    if not content:
        raise HTTPException(status_code=400, detail="Message content cannot be empty")
    messages.append({"sender": current_user["username"], "receiver": receiver, "content": content})
    return {"message": "Message sent successfully"}

@app.get("/messages")
async def get_messages(current_user: dict = Depends(get_current_user)):
    user_messages = [msg for msg in messages if msg["receiver"] == current_user["username"] or msg["sender"] == current_user["username"]]
    return {"messages": user_messages}

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)
    # uvicorn.run("main:app", host='0.0.0.0', port=8000, reload=True, workers=3)