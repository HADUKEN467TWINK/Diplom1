import redis.asyncio as redis
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Optional
import uvicorn
import asyncio
from mcp.server.fastmcp import FastMCP

app = FastAPI(title="Viewer_BDU")
mcp = FastMCP("MCP Server BDU")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_client = redis.Redis(
    host='my-redis',
    port=6379,
    decode_responses=True,
    socket_connect_timeout=5
)

async def init_mongo():
    await redis_client.ping()
    mongodb_url = "mongodb://mongodb:27017/"
    name_base = await redis_client.hget("my_config", "name_base")
    mongo_client = AsyncIOMotorClient(mongodb_url)
    base = mongo_client[name_base]
    return base, name_base

@app.on_event("startup")
async def startup():
    global base, name_base
    base, name_base = await init_mongo()

@app.get("/", response_class=HTMLResponse)
async def home():
    return FileResponse("templates/index_bdu.html")

@app.get("/api/bdu/items")
async def get_bdu_items(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    severity_text: Optional[str] = Query(None)
):
    try:
        if base is None:
            return JSONResponse(
                status_code=503,
                content={"status": False, "message": "MongoDB не доступна", "items": [], "total": 0}
            )

        collection = base["BDU"]
        filter_condition = {}
        
        if search and search.strip():
            filter_condition["_id"] = {"$regex": search.strip(), "$options": "i"}
        if severity_text and severity_text.strip():
            filter_condition["severity"] = {"$regex": severity_text.strip(), "$options": "i"}
        
        total = await collection.count_documents(filter_condition)
        skip = (page - 1) * limit
        cursor = collection.find(filter_condition).sort("_id", 1).skip(skip).limit(limit)
        items = await cursor.to_list(length=limit)
        
        return {
            "status": True,
            "items": items,
            "total": total,
            "page": page,
            "pageSize": limit,
            "totalPages": (total + limit - 1) // limit if total > 0 else 1
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": False, "message": str(e), "items": [], "total": 0}
        )

@app.get("/api/bdu/item/{bdu_id}")
async def get_bdu_item(bdu_id: str):
    try:
        if base is None:
            return JSONResponse(status_code=503, content={"status": False, "message": "MongoDB не доступна"})
        
        collection = base["BDU"]
        doc = await collection.find_one({"_id": bdu_id})
        
        if not doc:
            return JSONResponse(status_code=404, content={"status": False, "message": f"Запись {bdu_id} не найдена"})
        
        return {"status": True, "data": doc}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": False, "message": str(e)})

@app.get("/api/config")
async def get_config():
    return {
        "status": True,
        "config": {
            "name_base": name_base,
            "mongodb_connected": base is not None
        }
    }

@app.get("/api/db-status")
async def get_db_status():
    if base is None:
        return {"status": False, "message": "MongoDB не подключена"}
    
    try:
        collections = await base.list_collection_names()
        bdu_count = await base["BDU"].count_documents({}) if "BDU" in collections else 0
        
        return {
            "status": True,
            "message": "MongoDB подключена",
            "database": name_base,
            "collections": collections,
            "bdu_count": bdu_count
        }
    except Exception as e:
        return {"status": False, "message": f"Ошибка: {str(e)}"}

if __name__ == "__main__":
    base, name_base = asyncio.run(init_mongo())
    uvicorn.run("bdu_main:app", host="0.0.0.0", port=8004, reload=True)