from fastapi import APIRouter
from fastapi.responses import HTMLResponse, FileResponse
from src.help_func import update_cve_in_mongo, update_bdu_in_mongo, get_config_from_redis, redis_client
import os

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def home():
    return FileResponse("templates/index.html")

@router.get("/download-bdu-browser")
async def download_bdu_through_browser():
    """
    Открывает страницу для скачивания BDU файла через браузер
    """
    config = await get_config_from_redis()
    update_url_bdu = config.get("update_url_bdu")
    
    if not update_url_bdu:
        return HTMLResponse(content="""
            <html>
                <body style="text-align:center; padding:50px; font-family:Arial;">
                    <h1>❌ Ошибка</h1>
                    <p>URL для BDU не настроен в конфигурации</p>
                    <a href="/">Вернуться назад</a>
                </body>
            </html>
        """)
    
    html_path = "templates/index_d_bdu.html"
    if not os.path.exists(html_path):
        return HTMLResponse(content=f"""
            <html>
                <body style="text-align:center; padding:50px; font-family:Arial;">
                    <h1>❌ Ошибка</h1>
                    <p>Файл шаблона не найден: {html_path}</p>
                    <a href="/">Вернуться назад</a>
                </body>
            </html>
        """)
    
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    
    html_content = html_content.replace('{update_url_bdu}', update_url_bdu)
    
    return HTMLResponse(content=html_content)

@router.get("/download-cve-browser")
async def download_cve_through_browser():
    """
    Открывает страницу для скачивания CVE файла через браузер
    """
    config = await get_config_from_redis()
    update_url_cve = config.get("update_url_cve")
    
    if not update_url_cve:
        return HTMLResponse(content="""
            <html>
                <body style="text-align:center; padding:50px; font-family:Arial;">
                    <h1>❌ Ошибка</h1>
                    <p>URL для CVE не настроен в конфигурации</p>
                    <a href="/">Вернуться назад</a>
                </body>
            </html>
        """)
    
    html_path = "templates/index_d_cve.html"
    if not os.path.exists(html_path):
        return HTMLResponse(content=f"""
            <html>
                <body style="text-align:center; padding:50px; font-family:Arial;">
                    <h1>❌ Ошибка</h1>
                    <p>Файл шаблона не найден: {html_path}</p>
                    <a href="/">Вернуться назад</a>
                </body>
            </html>
        """)
    
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    
    html_content = html_content.replace('{update_url_cve}', update_url_cve)
    
    return HTMLResponse(content=html_content)

@router.get("/rep", summary="Получить файлы CVE и БДУ из Интернета", tags=["CVE"])
async def download_base():
    """
    Скачивает существующую базу данных CVE и BDU в сжатых архивах
    """
    config = await get_config_from_redis()
    update_url_cve = config.get("update_url_cve")
    update_url_bdu = config.get("update_url_bdu")
    
    if not update_url_cve or not update_url_bdu:
        return {
            "status": False,
            "message": "URL для обновления не настроен. Проверьте конфигурацию.",
            "config": config
        }
    
    results = []
    
    try:
        result = await update_cve_in_mongo(update_url_cve, use_browser=False)
        results.append(result)
    except Exception as e:
        results.append({
            "status": False,
            "message": f"Ошибка скачивания CVE: {str(e)}"
        })
    
    try:
        result = await update_bdu_in_mongo(update_url_bdu, use_browser=False)
        results.append(result)
    except Exception as e:
        results.append({
            "status": False,
            "message": f"Ошибка скачивания BDU: {str(e)}"
        })
    
    return results

@router.put("/rep", summary="Обновить базу данных CVE и БДУ", tags=["CVE"])
async def update_base():
    """
    Обновляет существующую базу данных CVE и BDU в MongoDB
    """
    config = await get_config_from_redis()
    update_url_cve = config.get("update_url_cve")
    update_url_bdu = config.get("update_url_bdu")
    
    if not update_url_cve or not update_url_bdu:
        return {
            "status": False,
            "message": "URL для обновления не настроен. Проверьте конфигурацию.",
            "config": config
        }
    
    update_cve_result = await update_cve_in_mongo(update_url_cve, use_browser=False)
    update_bdu_result = await update_bdu_in_mongo(update_url_bdu, use_browser=False)
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