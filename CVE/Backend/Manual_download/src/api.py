from fastapi import APIRouter
import redis.asyncio as redis
from src.help_func import clone_cve_in_mongo, clone_bdu_xml_in_mongo
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

@router.post("/", summary="Скачать базу данных CVE и БДУ", tags=["CVE"])
async def download_base():
    """
    Скачивает базу данных CVE и сохраняет её в MongoDB
    """
    config = await get_config_from_redis()

    if not config["filename_cve"] or not config["filename_bdu"]:
        return {
            "status": False,
            "message": "Не указано имя файла. Сначала установите конфигурацию через /rep"
        }

    clone_result_cve = await clone_cve_in_mongo(config["filename_cve"])
    clone_result_bdu = await clone_bdu_xml_in_mongo(config["filename_bdu"])
    return clone_result_cve, clone_result_bdu


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