from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from .deps import get_current_user, get_db
from .models import Item

app = FastAPI()


class ItemIn(BaseModel):
    name: str


@app.post("/items")
def create_item(item: ItemIn, user=Depends(get_current_user), db=Depends(get_db)):
    row = Item(name=item.name, owner_id=user.id)
    db.add(row)
    db.commit()
    return {"id": row.id}


@app.get("/items/{item_id}")
def read_item(item_id: int, user=Depends(get_current_user), db=Depends(get_db)):
    row = db.get(Item, item_id)
    if row is None or row.owner_id != user.id:
        raise HTTPException(status_code=404)
    return row
