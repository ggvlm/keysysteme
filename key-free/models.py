from __future__ import annotations
from typing import Optional
from sqlmodel import Field, SQLModel


class Key(SQLModel, table=True):
    __tablename__ = "key"

    id: Optional[int] = Field(default=None, primary_key=True)
    value: str = Field(index=True, unique=True)
    is_used: bool = Field(default=False)
