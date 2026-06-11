import os
import json
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Dict, List
import bcrypt

# Database models import karna
from database import SessionLocal, User, Room, RoomMember, Message

app = FastAPI(title="Secure Chat & Video App Backend")

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
    username: str

class RoomJoin(BaseModel):
    room_name: str
    secret_key: str
    username: str

# --- FRONTEND ROUTE ---
@app.get("/")
def get_frontend():
    return FileResponse("index.html")

# --- ADMIN / DASHBOARD ROUTES ---
@app.get("/admin/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return {"total_users_registered": len(users), "user_names": [u.username for u in users]}

@app.get("/admin/live")
def get_live_connections():
    live_data = {}
    total_live_users = 0
    for room_name, connections in manager.active_rooms.items():
        count = len(connections)
        live_data[room_name] = count
        total_live_users += count
    return {"total_live_users_right_now": total_live_users, "rooms_data": live_data}

@app.get("/admin/db-stats")
def get_db_stats(db: Session = Depends(get_db)):
    return {
        "total_registered_users": db.query(User).count(),
        "total_created_rooms": db.query(Room).count(),
        "total_chat_messages": db.query(Message).count()
    }

# --- AUTH ROUTES ---
@app.post("/signup")
def signup(user: UserAuth, db: Session = Depends(get_db)):
    if not user.password or len(user.password.strip()) == 0:
        raise HTTPException(status_code=400, detail="Password cannot be empty.")
        
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken.")
    
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
        raise HTTPException(status_code=400, detail="Room name already exists.")
    
    new_room = Room(name=room_data.room_name, secret_key=room_data.secret_key)
    db.add(new_room)
    db.commit()
    db.refresh(new_room)
    
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
        raise HTTPException(status_code=403, detail="Incorrect Room Password.")
        
    existing_member = db.query(RoomMember).filter(RoomMember.user_id == user.id, RoomMember.room_id == room.id).first()
    if not existing_member:
        new_member = RoomMember(user_id=user.id, room_id=room.id)
        db.add(new_member)
        db.commit()
    return {"message": f"Successfully joined {room.name}"}

@app.get("/rooms/{username}")
def get_user_rooms(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user: return []
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

    async def broadcast(self, message: str, room_name: str, exclude_ws: WebSocket = None):
        if room_name in self.active_rooms:
            for connection in self.active_rooms[room_name]:
                if connection != exclude_ws:
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
        
    is_member = db.query(RoomMember).filter(RoomMember.user_id == user.id, RoomMember.room_id == room.id).first()
    if not is_member:
        await websocket.close()
        db.close()
        return

    await manager.connect(websocket, room_name)
    
    # Load Past Messages (Plain text history)
    past_messages = db.query(Message).filter(Message.room_id == room.id).order_by(Message.timestamp).all()
    for msg in past_messages:
        sender = db.query(User).filter(User.id == msg.user_id).first()
        sender_name = sender.username if sender else "Unknown"
        await websocket.send_text(f"{sender_name}:{msg.text}")

    try:
        await manager.broadcast(f"** {username} joined the chat **", room_name, exclude_ws=websocket)
        while True:
            raw_data = await websocket.receive_text()
            
            try:
                payload = json.loads(raw_data)
                msg_type = payload.get("type")
                
                # 1. NORMAL CHAT MESSAGE
                if msg_type == "chat_message":
                    msg_id = payload.get("id")
                    text_content = payload.get("text")
                    
                    # Save to DB
                    new_msg = Message(text=text_content, room_id=room.id, user_id=user.id)
                    db.add(new_msg)
                    db.commit()
                    
                    # Send Sent ACK (Single Tick)
                    ack_receipt = {"type": "ack", "id": msg_id, "status": "sent"}
                    await websocket.send_text(json.dumps(ack_receipt))
                    
                    # Broadcast to room
                    broadcast_data = {"type": "chat_message", "id": msg_id, "user_id": username, "text": text_content}
                    await manager.broadcast(json.dumps(broadcast_data), room_name, exclude_ws=websocket)
                
                # 2. DELIVERY RECEIPT (Double Tick)
                elif msg_type == "delivery_ack":
                    delivered_msg_id = payload.get("message_id")
                    status_update = {"type": "status_update", "id": delivered_msg_id, "status": "delivered"}
                    await manager.broadcast(json.dumps(status_update), room_name, exclude_ws=websocket)
                    
                # 3. WEBRTC SIGNALING (Do Not Save to Database)
                elif msg_type in ["webrtc_offer", "webrtc_answer", "webrtc_ice_candidate"]:
                    # Just pass the signaling message to the other user in the room
                    await manager.broadcast(json.dumps(payload), room_name, exclude_ws=websocket)
                    
            except json.JSONDecodeError:
                # Fallback for plain text
                new_msg = Message(text=raw_data, room_id=room.id, user_id=user.id)
                db.add(new_msg)
                db.commit()
                await manager.broadcast(f"{username}:{raw_data}", room_name, exclude_ws=websocket)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket, room_name)
        await manager.broadcast(f"** {username} left the chat **", room_name)
    finally:
        db.close()