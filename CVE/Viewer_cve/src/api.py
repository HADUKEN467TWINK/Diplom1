from fastapi import APIRouter
import redis.asyncio as redis
from src.help_func import update_cve_in_mongo, update_bdu_in_mongo
from pydantic import BaseModel, HttpUrl

router = APIRouter()

redis_client = redis.Redis(
    host='my-redis',
    port=6379,
    decode_responses=True,
    socket_connect_timeout=5
)

class Repo_Schema(BaseModel):
    filename_cve: str
    filename_bdu: str
    update_url_cve: HttpUrl
    update_url_bdu: HttpUrl
    name_base: str

async def get_config_from_redis():
    """Получить конфигурацию из Redis"""
    try:
        config = await redis_client.hgetall("my_config")
        if not config:
            return {
                "filename_cve": "",
                "filename_bdu": "",
                "update_url_cve": "",
                "update_url_bdu": "",
                "name_base": ""
            }
        return config
    except Exception as e:
        print(f"Redis error: {e}")
        return {
            "filename_cve": "",
            "filename_bdu": "",
            "update_url_cve": "",
            "update_url_bdu": "",
            "name_base": ""
        }


@router.put("/rep", summary="Обновить базу данных CVE и БДУ", tags=["CVE"])
async def update_base():
    """
    Обновляет существующую базу данных CVE и BDU в MongoDB
    """
    config = await get_config_from_redis()
    update_url_cve = config["update_url_cve"]
    update_url_bdu = config["update_url_bdu"]
    if not update_url_cve or not update_url_bdu:
        return {
            "status": False,
            "message": "URL для обновления не настроен. Проверьте конфигурацию."
        }
    
    update_cve_result = await update_cve_in_mongo(update_url_cve)
    update_bdu_result = await update_bdu_in_mongo(update_url_bdu)
    return update_cve_result, update_bdu_result

@router.get("/config", summary="Получить текущую конфигурацию", tags=["CVE"])
async def get_current_config():
    """
    Получить текущую конфигурацию из Redis
    """
    config = await get_config_from_redis()
    return {
        "status": True,
        "config": config
    }



