import jwt
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .deps import get_current_user, get_db
from .models import User

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)


@app.post("/items")
async def create_item(request: Request, db=Depends(get_db)):
    payload = await request.json()
    db.execute(text(f"INSERT INTO items (name) VALUES ('{payload['name']}')"))
    db.commit()
    return {"ok": True}


@app.get("/users/{user_id}")
def read_user(user_id: int, current=Depends(get_current_user), db=Depends(get_db)):
    return db.query(User).filter(User.id == user_id).first()


def make_token(user_id: int) -> str:
    return jwt.encode({"sub": user_id}, "secret", algorithm="HS256")
