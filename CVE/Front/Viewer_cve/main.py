import redis.asyncio as redis
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from typing import Optional
import uvicorn
import asyncio
from mcp.server.fastmcp import FastMCP
from bson import ObjectId

app = FastAPI(title="Viewer_CVE")
mcp = FastMCP("MCP Server")
app.mount("/mcp", mcp.sse_app())

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

def convert_objectid(obj):
    """Рекурсивно преобразует ObjectId в строку"""
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, dict):
        return {key: convert_objectid(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [convert_objectid(item) for item in obj]
    return obj

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
    return FileResponse("templates/index.html")

def get_severity_from_score(baseScore):
    if baseScore is None:
        return 'UNKNOWN'
    if baseScore == 0.0:
        return 'NONE'
    elif baseScore < 4.0:
        return 'LOW'
    elif baseScore < 7.0:
        return 'MEDIUM'
    elif baseScore < 9.0:
        return 'HIGH'
    else:
        return 'CRITICAL'

def get_cve_severity(cve_item):
    all_scores = []
    priority_versions = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']
    
    for metric in cve_item.get('containers', {}).get('cna', {}).get('metrics', []):
        for version in priority_versions:
            if version in metric:
                score = metric[version].get('baseScore')
                if score is not None:
                    all_scores.append(float(score))
    
    for adp_item in cve_item.get('containers', {}).get('adp', []):
        for metric in adp_item.get('metrics', []):
            for version in priority_versions:
                if version in metric:
                    score = metric[version].get('baseScore')
                    if score is not None:
                        all_scores.append(float(score))
    
    if all_scores:
        max_score = max(all_scores)
        return {
            'score': max_score,
            'severity': get_severity_from_score(max_score)
        }
    return {'score': None, 'severity': 'UNKNOWN'}

@app.get("/api/config")
async def get_config():
    return {
        "status": True,
        "config": {
            "name_base": name_base,
            "mongodb_connected": base is not None
        }
    }

@mcp.tool()
@app.get("/api/cves")
async def get_cves(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None)
):
    try:
        if base is None:
            return JSONResponse(
                status_code=503,
                content={"status": False, "message": "MongoDB не доступна", "items": [], "total": 0}
            )

        collection = base["CVE"]
        pipeline = []
        
        if search and search.strip():
            pipeline.append({
                "$match": {"cveMetadata.cveId": {"$regex": search.strip(), "$options": "i"}}
            })
        
        pipeline.append({
            "$addFields": {
                "all_scores": {
                    "$concatArrays": [
                        {
                            "$reduce": {
                                "input": "$containers.cna.metrics",
                                "initialValue": [],
                                "in": {
                                    "$concatArrays": [
                                        "$$value",
                                        {
                                            "$filter": {
                                                "input": [
                                                    "$$this.cvssV4_0.baseScore",
                                                    "$$this.cvssV3_1.baseScore",
                                                    "$$this.cvssV3_0.baseScore",
                                                    "$$this.cvssV2_0.baseScore"
                                                ],
                                                "as": "score",
                                                "cond": {"$ne": ["$$score", None]}
                                            }
                                        }
                                    ]
                                }
                            }
                        },
                        {
                            "$reduce": {
                                "input": "$containers.adp",
                                "initialValue": [],
                                "in": {
                                    "$concatArrays": [
                                        "$$value",
                                        {
                                            "$reduce": {
                                                "input": "$$this.metrics",
                                                "initialValue": [],
                                                "in": {
                                                    "$concatArrays": [
                                                        "$$value",
                                                        {
                                                            "$filter": {
                                                                "input": [
                                                                    "$$this.cvssV4_0.baseScore",
                                                                    "$$this.cvssV3_1.baseScore",
                                                                    "$$this.cvssV3_0.baseScore",
                                                                    "$$this.cvssV2_0.baseScore"
                                                                ],
                                                                "as": "score",
                                                                "cond": {"$ne": ["$$score", None]}
                                                            }
                                                        }
                                                    ]
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        })
        
        pipeline.append({
            "$addFields": {
                "max_cvss_score": {"$max": "$all_scores"}
            }
        })
        
        if severity and severity.strip():
            severity_upper = severity.upper()
            ranges = {
                'NONE': (0.0, 0.0),
                'LOW': (0.1, 3.9),
                'MEDIUM': (4.0, 6.9),
                'HIGH': (7.0, 8.9),
                'CRITICAL': (9.0, 10.0)
            }
            
            if severity_upper in ranges:
                min_score, max_score = ranges[severity_upper]
                if severity_upper == 'NONE':
                    pipeline.append({
                        "$match": {"$or": [{"max_cvss_score": None}, {"max_cvss_score": 0.0}]}
                    })
                else:
                    pipeline.append({
                        "$match": {"max_cvss_score": {"$gte": min_score, "$lte": max_score}}
                    })
        
        pipeline.append({
            "$addFields": {
                "severity_info": {
                    "score": "$max_cvss_score",
                    "severity": {
                        "$switch": {
                            "branches": [
                                {"case": {"$or": [{"$eq": ["$max_cvss_score", None]}, {"$eq": ["$max_cvss_score", 0.0]}]}, "then": "NONE"},
                                {"case": {"$lt": ["$max_cvss_score", 4.0]}, "then": "LOW"},
                                {"case": {"$lt": ["$max_cvss_score", 7.0]}, "then": "MEDIUM"},
                                {"case": {"$lt": ["$max_cvss_score", 9.0]}, "then": "HIGH"}
                            ],
                            "default": "CRITICAL"
                        }
                    }
                }
            }
        })
        
        pipeline.append({"$sort": {"severity_info.severity": 1, "cveMetadata.cveId": 1}})
        
        count_pipeline = [s for s in pipeline if "$skip" not in s and "$limit" not in s and "$sort" not in s]
        count_pipeline.append({"$count": "total"})
        count_result = await collection.aggregate(count_pipeline).to_list(length=1)
        total = count_result[0]["total"] if count_result else 0
        
        pipeline.append({"$skip": (page - 1) * limit})
        pipeline.append({"$limit": limit})
        
        items = await collection.aggregate(pipeline).to_list(length=limit)
        
        for item in items:
            item.pop("all_scores", None)
            # Преобразуем ObjectId в строку
            if "_id" in item:
                item["_id"] = str(item["_id"])
        
        # Преобразуем все ObjectId в items
        items = convert_objectid(items)
        
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

@mcp.tool()
@app.get("/api/cve/{cve_id}")
async def get_cve_by_id(cve_id: str):
    try:
        if base is None:
            return JSONResponse(status_code=503, content={"status": False, "message": "MongoDB не доступна"})
        
        collection = base["CVE"]
        doc = await collection.find_one({"cveMetadata.cveId": cve_id})
        
        if not doc:
            return JSONResponse(status_code=404, content={"status": False, "message": f"CVE {cve_id} не найдена"})
        
        doc["severity_info"] = get_cve_severity(doc)
        # Преобразуем ObjectId в строку
        doc = convert_objectid(doc)
        return {"status": True, "data": doc}
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"status": False, "message": str(e)})

@app.get("/api/db-status")
async def get_db_status():
    if base is None:
        return {"status": False, "message": "MongoDB не подключена"}
    
    try:
        cve_count = await base["CVE"].count_documents({})
        return {
            "status": True,
            "message": "MongoDB подключена",
            "database": name_base,
            "cve_count": cve_count
        }
    except Exception as e:
        return {"status": False, "message": f"Ошибка: {str(e)}"}

if __name__ == "__main__":
    base, name_base = asyncio.run(init_mongo())
    uvicorn.run("main:app", host="0.0.0.0", port=8003, reload=True)