from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
import uvicorn

from pymongo import MongoClient, ASCENDING
from bson.objectid import ObjectId

app = FastAPI()

DATABASE_URL = "postgresql://user:password@db:5432/messenger"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])

Base.metadata.create_all(bind=engine)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

MONGO_URL = "mongodb://mongodb:27017"
mongo_client = MongoClient(MONGO_URL)
mongo_db = mongo_client.messenger
messages_collection = mongo_db.messages

@app.on_event("startup")
def setup_mongo_indexes():
    messages_collection.create_index([("sender_id", ASCENDING)])
    messages_collection.create_index([("receiver_id", ASCENDING)])
    print("MongoDB indexes created successfully.")

@app.post("/messages/send")
async def send_message_mongo(receiver: str, content: str, current_user: User = Depends(get_current_user), db=Depends(get_db)):
    receiver_user = db.query(User).filter(User.username == receiver).first()
    if not receiver_user:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
    message = {
        "sender_id": current_user.id,
        "receiver_id": receiver_user.id,
        "content": content,
        "timestamp": datetime.utcnow()
    }
    result = messages_collection.insert_one(message)
    return {"message": "Message sent successfully", "message_id": str(result.inserted_id)}

@app.get("/messages")
async def get_messages_mongo(current_user: User = Depends(get_current_user)):
    query = {"$or": [{"sender_id": current_user.id}, {"receiver_id": current_user.id}]}
    messages = messages_collection.find(query).sort("timestamp", ASCENDING)
    
    return {
        "messages": [
            {
                "id": str(msg["_id"]),
                "content": msg["content"],
                "timestamp": msg["timestamp"]
            }
            for msg in messages
        ]
    }
   
@app.on_event("startup")
def add_master_user():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            hashed_password = hash_password("secret")
            admin_user = User(username="admin", hashed_password=hashed_password)
            db.add(admin_user)
            db.commit()
            print("Master user 'admin' created successfully.")
        else:
            print("Master user 'admin' already exists.")
    finally:
        db.close()

@app.post("/register")
def register(username: str, password: str, db=Depends(get_db)):
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_password = hash_password(password)
    user = User(username=username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"message": "User registered successfully"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user.username)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/messages/send")
async def send_message(receiver: str, content: str, current_user: User = Depends(get_current_user), db=Depends(get_db)):
    receiver_user = db.query(User).filter(User.username == receiver).first()
    if not receiver_user:
        raise HTTPException(status_code=404, detail="Receiver not found")
    message = Message(sender_id=current_user.id, receiver_id=receiver_user.id, content=content)
    db.add(message)
    db.commit()
    return {"message": "Message sent successfully"}

@app.get("/messages")
async def get_messages(current_user: User = Depends(get_current_user), db=Depends(get_db)):
    messages = db.query(Message).filter((Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)).all()
    return {"messages": [{"id": msg.id, "content": msg.content, "timestamp": msg.timestamp} for msg in messages]}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
    