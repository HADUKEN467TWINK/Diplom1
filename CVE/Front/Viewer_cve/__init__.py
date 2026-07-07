from fastapi import APIRouter
from src.api import router as rtr 

app = APIRouter()

app.include_router(rtr)
