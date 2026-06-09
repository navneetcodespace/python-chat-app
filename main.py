from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, List
import bcrypt

# Database models import karna (Yahan RoomMember bhi add kiya hai)
from database import SessionLocal, User, Room, RoomMember, Message

app = FastAPI(title="Secure Chat App Backend")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- SECURITY ---
def get_password_hash(password: str):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# --- SCHEMAS ---
class UserAuth(BaseModel):
    username: str
    password: str

class RoomCreate(BaseModel):
    room_name: str
    secret_key: str
    username: str  # Pata karne ke liye ki kisne room banaya

class RoomJoin(BaseModel):
    room_name: str
    secret_key: str
    username: str

# --- FRONTEND ROUTE ---
@app.get("/")
def get_frontend():
    return FileResponse("index.html")

# --- AUTH ROUTES ---
@app.post("/signup")
def signup(user: UserAuth, db: Session = Depends(get_db)):
    # 1. Empty password check
    if not user.password or len(user.password.strip()) == 0:
        raise HTTPException(status_code=400, detail="Password cannot be empty.")
        
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken. Please choose a unique handle.")
    
    hashed_pw = get_password_hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_pw)
    db.add(new_user)
    db.commit()
    return {"message": "Account created successfully!", "username": new_user.username}

@app.post("/login")
def login(user: UserAuth, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    return {"message": "Login successful!", "username": db_user.username}

# --- ROOM ROUTES ---
@app.post("/rooms/create")
def create_room(room_data: RoomCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == room_data.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing_room = db.query(Room).filter(Room.name == room_data.room_name).first()
    if existing_room:
        raise HTTPException(status_code=400, detail="Room name already exists. Choose another.")
    
    # Room banayein with Secret Key
    new_room = Room(name=room_data.room_name, secret_key=room_data.secret_key)
    db.add(new_room)
    db.commit()
    db.refresh(new_room)
    
    # Jisne room banaya hai usko automatically room ka member bana dein
    new_member = RoomMember(user_id=user.id, room_id=new_room.id)
    db.add(new_member)
    db.commit()
    
    return {"message": "Room created successfully!", "room_name": new_room.name}

@app.post("/rooms/join")
def join_room(room_data: RoomJoin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == room_data.username).first()
    room = db.query(Room).filter(Room.name == room_data.room_name).first()
    
    if not room:
        raise HTTPException(status_code=404, detail="Room not found.")
    if room.secret_key != room_data.secret_key:
        raise HTTPException(status_code=403, detail="Incorrect Room Password/Key.")
        
    # Check karein agar user pehle se member hai
    existing_member = db.query(RoomMember).filter(RoomMember.user_id == user.id, RoomMember.room_id == room.id).first()
    if not existing_member:
        new_member = RoomMember(user_id=user.id, room_id=room.id)
        db.add(new_member)
        db.commit()
        
    return {"message": f"Successfully joined {room.name}"}

@app.get("/rooms/{username}")
def get_user_rooms(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return []
        
    # Sirf wahi rooms fetch karein jiska user member hai
    memberships = db.query(RoomMember).filter(RoomMember.user_id == user.id).all()
    room_ids = [m.room_id for m in memberships]
    
    user_rooms = db.query(Room).filter(Room.id.in_(room_ids)).all()
    return [{"room_name": r.name} for r in user_rooms]

# --- WEBSOCKET CHAT MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_rooms: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, room_name: str):
        await websocket.accept()
        if room_name not in self.active_rooms:
            self.active_rooms[room_name] = []
        self.active_rooms[room_name].append(websocket)

    def disconnect(self, websocket: WebSocket, room_name: str):
        if room_name in self.active_rooms and websocket in self.active_rooms[room_name]:
            self.active_rooms[room_name].remove(websocket)

    async def broadcast(self, message: str, room_name: str):
        if room_name in self.active_rooms:
            for connection in self.active_rooms[room_name]:
                await connection.send_text(message)

manager = ConnectionManager()

# --- WEBSOCKET ENDPOINT ---
@app.websocket("/ws/{room_name}/{username}")
async def chat_endpoint(websocket: WebSocket, room_name: str, username: str):
    db = SessionLocal()
    room = db.query(Room).filter(Room.name == room_name).first()
    user = db.query(User).filter(User.username == username).first()
    
    if not room or not user:
        await websocket.close()
        db.close()
        return
        
    # SECURITY CHECK: WebSocket connect hone se pehle check karein ki kya user is room ka member hai?
    is_member = db.query(RoomMember).filter(RoomMember.user_id == user.id, RoomMember.room_id == room.id).first()
    if not is_member:
        await websocket.close()
        db.close()
        return

    await manager.connect(websocket, room_name)
    
    past_messages = db.query(Message).filter(Message.room_id == room.id).order_by(Message.timestamp).all()
    for msg in past_messages:
        sender = db.query(User).filter(User.id == msg.user_id).first()
        sender_name = sender.username if sender else "Unknown"
        await websocket.send_text(f"{sender_name}: {msg.text}")

    try:
        await manager.broadcast(f"** {username} joined the chat **", room_name)
        while True:
            data = await websocket.receive_text()
            new_msg = Message(text=data, room_id=room.id, user_id=user.id)
            db.add(new_msg)
            db.commit()
            await manager.broadcast(f"{username}: {data}", room_name)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket, room_name)
        await manager.broadcast(f"** {username} left the chat **", room_name)
    finally:
        db.close()

# --- FRONTEND ROUTE ---
@app.get("/")
def get_frontend():
    return FileResponse("index.html")