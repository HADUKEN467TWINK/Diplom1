import os
import redis.asyncio as redis
from fastapi import FastAPI, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn

# ==================== КОНФИГ ====================
REDIS_HOST = os.getenv("REDIS_HOST", "my-redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_KEY = "my_config"


# ==================== PYDANTIC МОДЕЛИ ====================
class ConfigUpdate(BaseModel):
    mongodb_url: Optional[str] = None
    filename_cve: Optional[str] = None
    filename_bdu: Optional[str] = None
    update_url_cve: Optional[str] = None
    update_url_bdu: Optional[str] = None
    name_base: Optional[str] = None


# ==================== REDIS ФУНКЦИИ ====================
async def get_redis():
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True
    )


async def get_config() -> dict:
    r = await get_redis()
    config = await r.hgetall(REDIS_KEY)
    await r.close()

    if not config:
        default_config = {
            "mongodb_url": "mongodb://mongodb:27017/",
            "filename_cve": "CVE_start.zip",
            "filename_bdu": "bdu_test_12.xml",
            "update_url_cve": "https://gitea.com/HADUKEN/TEST_CVE/raw/branch/main/CVE_main1.zip",
            "update_url_bdu": "https://github.com/HADUKEN467/TEST_CVE_BDU/raw/master/bdu_test_500.xml",
            "name_base": "bd"
        }
        r = await get_redis()
        await r.hset(REDIS_KEY, mapping=default_config)
        await r.close()
        return default_config

    return config


async def update_config(data: dict) -> dict:
    r = await get_redis()
    for key, value in data.items():
        if value is not None:
            await r.hset(REDIS_KEY, key, value)
    updated = await r.hgetall(REDIS_KEY)
    await r.close()
    return updated


async def delete_config_key(key: str):
    r = await get_redis()
    await r.hdel(REDIS_KEY, key)
    await r.close()


# ==================== FASTAPI APP ====================
app = FastAPI(title="Config Manager")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Jinja2
templates = Jinja2Templates(directory="templates")


# ==================== API РОУТЫ (JSON) ====================
@app.get("/api/config")
async def api_get_config():
    return await get_config()


@app.put("/api/config")
async def api_update_config(config_update: ConfigUpdate):
    update_data = {k: v for k, v in config_update.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(400, "No data to update")
    return await update_config(update_data)


@app.delete("/api/config/{key}")
async def api_delete_key(key: str):
    valid_keys = ["mongodb_url", "filename_cve", "filename_bdu",
                  "update_url_cve", "update_url_bdu", "name_base"]
    if key not in valid_keys:
        raise HTTPException(400, f"Invalid key: {key}")
    await delete_config_key(key)
    return {"message": f"Key '{key}' deleted"}


@app.get("/api/health")
async def health_check():
    try:
        config = await get_config()
        return {"status": "ok", "redis_connected": bool(config)}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ==================== HTML СТРАНИЦЫ (Jinja2 + HTMX) ====================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    config = await get_config()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "config": config,
        "redis_host": REDIS_HOST,
        "redis_port": REDIS_PORT,
        "redis_key": REDIS_KEY
    })


# HTMX эндпоинты (возвращают ТОЛЬКО HTML-кусочки)

@app.get("/partial/config-display", response_class=HTMLResponse)
async def partial_config_display(request: Request):
    """Возвращает только блок с отображением настроек"""
    config = await get_config()
    return templates.TemplateResponse("partials/config_display.html", {
        "request": request,
        "config": config
    })


@app.post("/partial/save-config", response_class=HTMLResponse)
async def partial_save_config(request: Request):
    """Сохраняет настройки и возвращает обновленный блок"""
    form_data = await request.form()

    update_data = {
        "mongodb_url": form_data.get("mongodb_url"),
        "filename_cve": form_data.get("filename_cve"),
        "filename_bdu": form_data.get("filename_bdu"),
        "update_url_cve": form_data.get("update_url_cve"),
        "update_url_bdu": form_data.get("update_url_bdu"),
        "name_base": form_data.get("name_base")
    }

    # Убираем пустые значения
    update_data = {k: v for k, v in update_data.items() if v and v.strip()}

    if update_data:
        await update_config(update_data)

    config = await get_config()
    return templates.TemplateResponse("partials/config_display.html", {
        "request": request,
        "config": config,
        "success": True
    })


@app.delete("/partial/delete-key/{key}", response_class=HTMLResponse)
async def partial_delete_key(request: Request, key: str):
    """Удаляет ключ и возвращает обновленный блок"""
    valid_keys = ["mongodb_url", "filename_cve", "filename_bdu",
                  "update_url_cve", "update_url_bdu", "name_base"]
    if key in valid_keys:
        await delete_config_key(key)

    config = await get_config()
    return templates.TemplateResponse("partials/config_display.html", {
        "request": request,
        "config": config
    })


@app.post("/partial/reset-default", response_class=HTMLResponse)
async def partial_reset_default(request: Request):
    """Сбрасывает настройки к дефолтным"""
    default_config = {
        "mongodb_url": "mongodb://mongodb:27017/",
        "filename_cve": "CVE_start.zip",
        "filename_bdu": "bdu_test_12.xml",
        "update_url_cve": "https://gitea.com/HADUKEN/TEST_CVE/raw/branch/main/CVE_main1.zip",
        "update_url_bdu": "https://github.com/HADUKEN467/TEST_CVE_BDU/raw/master/bdu_test_500.xml",
        "name_base": "bd"
    }
    await update_config(default_config)
    config = await get_config()
    return templates.TemplateResponse("partials/config_display.html", {
        "request": request,
        "config": config,
        "success": True
    })


# ==================== ЗАПУСК ====================
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)