import logging

from fastapi import Depends, FastAPI, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import get_current_user
from .db import get_db
from .models import Item

app = FastAPI()
logger = logging.getLogger(__name__)


class ItemIn(BaseModel):
    name: str


@app.get("/items")
def list_items(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(select(Item).where(Item.owner_id == user.id).limit(50)).all()


@app.get("/items/{item_id}")
def read_item(item_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    item = db.scalar(select(Item).where(Item.id == item_id, Item.owner_id == user.id))
    if item is None:
        raise HTTPException(status_code=404)
    return item


@app.post("/items")
def create_item(body: ItemIn, user=Depends(get_current_user), db: Session = Depends(get_db)):
    item = Item(name=body.name, owner_id=user.id)
    db.add(item)
    db.commit()
    logger.info("user %s created an item", user.id)
    return item


@app.get("/health")
def health():
    return {"status": "ok"}
