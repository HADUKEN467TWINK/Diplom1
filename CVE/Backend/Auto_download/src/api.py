from fastapi import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse
import redis.asyncio as redis
from src.help_func import update_cve_in_mongo, update_bdu_in_mongo, download_url
from pydantic import BaseModel, HttpUrl
from pathlib import Path
import os
from fastapi import Query

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

@router.get("/", response_class=HTMLResponse)
async def home():
    html_content = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE/BDU Управление базами данных</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }

        .header h1 {
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            color: #666;
            font-size: 1.1em;
        }

        .status-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin-top: 10px;
            background: #4CAF50;
            color: white;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }

        .card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            transition: transform 0.3s ease;
        }

        .card:hover {
            transform: translateY(-5px);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }

        .card-header h2 {
            color: #333;
            font-size: 1.3em;
        }

        .method-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }

        .method-get {
            background: #2196F3;
        }

        .method-put {
            background: #FF9800;
        }

        .card-body {
            color: #666;
        }

        .card-body p {
            margin-bottom: 15px;
            line-height: 1.6;
        }

        .btn {
            padding: 10px 25px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            color: white;
            width: 100%;
        }

        .btn-get {
            background: #2196F3;
        }

        .btn-get:hover {
            background: #1976D2;
            transform: scale(1.02);
        }

        .btn-put {
            background: #FF9800;
        }

        .btn-put:hover {
            background: #F57C00;
            transform: scale(1.02);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .result-container {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            margin-top: 20px;
            max-height: 400px;
            overflow: auto;
            display: none;
        }

        .result-container.show {
            display: block;
        }

        .result-container pre {
            margin: 0;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #333;
            font-family: 'Courier New', monospace;
        }

        .status-bar {
            background: white;
            border-radius: 15px;
            padding: 20px 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }

        .status-text {
            font-weight: 600;
        }

        .status-ready {
            color: #4CAF50;
        }

        .status-loading {
            color: #FF9800;
        }

        .status-error {
            color: #d32f2f;
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }

            .grid {
                grid-template-columns: 1fr;
            }

            .card {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    
    <div class="container">
        <div class="header">
            <h1>CVE/BDU Скачать бесплатно</h1>
            <p>Скачивание и обновление баз данных уязвимостей CVE и БДУ</p>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <h2>Скачать в браузере</h2>
                </div>
                <div class="card-body">
                    <p>Открывает страницу в браузере для скачивания файлов CVE и BDU напрямую в папку "Загрузки"</p>
                    <div style="display: flex; gap: 10px;">
                        <button class="btn btn-get" onclick="window.open('/download-cve-browser', '_blank')" style="flex: 1;">
                            CVE
                        </button>
                        <button class="btn btn-get" onclick="window.open('/download-bdu-browser', '_blank')" style="flex: 1; background: #f5576c;">
                            BDU
                        </button>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2>Конфигурация</h2>
                </div>
                <div class="card-body">
                    <p>Просмотр текущей конфигурации из Redis</p>
                    <button class="btn btn-get" onclick="callAPI('GET', '/config', 'result3')">Показать конфигурацию</button>
                    <div id="result3" class="result-container"><pre></pre></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function updateTime() {
            const now = new Date();
            const timeEl = document.getElementById('timeText');
            if (timeEl) {
                timeEl.textContent = now.toLocaleString('ru-RU');
            }
        }
        updateTime();
        setInterval(updateTime, 1000);

        async function callAPI(method, endpoint, resultId) {
            const resultDiv = document.getElementById(resultId);
            if (!resultDiv) {
                console.error('Element not found:', resultId);
                return;
            }
            
            const pre = resultDiv.querySelector('pre');
            if (!pre) {
                console.error('Pre element not found in:', resultId);
                return;
            }
            
            const button = resultDiv.parentElement.querySelector('.btn');
            const statusText = document.getElementById('statusText');

            resultDiv.classList.add('show');
            if (button) {
                button.disabled = true;
                button.innerHTML = 'Загрузка...';
            }

            pre.textContent = '';

            if (statusText) {
                statusText.textContent = 'Выполняется запрос...';
                statusText.className = 'status-text status-loading';
            }

            try {
                const url = window.location.origin + endpoint;
                console.log('Calling:', method, url);

                const response = await fetch(url, {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });

                const data = await response.json();
                console.log('Response:', data);

                let output = '';

                if (endpoint === '/config') {
                    if (data.status && data.config) {
                        output = 'Текущая конфигурация:\\n\\n';
                        for (const [key, value] of Object.entries(data.config)) {
                            output += `${key}: ${value || '(не задано)'}\\n`;
                        }
                    } else {
                        output = JSON.stringify(data, null, 2);
                    }
                } else if (Array.isArray(data)) {
                    output = 'Результаты скачивания:\\n\\n';
                    data.forEach((item, index) => {
                        output += `Файл ${index + 1}:\\n`;
                        if (item.status) {
                            output += `${item.message}\\n`;
                        }
                        else {
                            output += `${item.message}\\n`;
                        }
                        output += '\\n';
                    });
                } else if (data.status !== undefined && data.statistics) {
                    output = 'Статистика обновления:\\n\\n';
                    output += `Статус: ${data.status ? 'Успешно' : 'Ошибка'}\\n`;
                    output += `Сообщение: ${data.message || 'Нет данных'}\\n\\n`;

                    if (data.statistics) {
                        output += 'Детали:\\n';
                        for (const [key, value] of Object.entries(data.statistics)) {
                            output += `${key}: ${value}\\n`;
                        }
                    }
                } else {
                    output = JSON.stringify(data, null, 2);
                }

                pre.textContent = output;

                if (statusText) {
                    if (response.ok) {
                        statusText.textContent = 'Готов к работе';
                        statusText.className = 'status-text status-ready';
                    } else {
                        statusText.textContent = 'Ошибка запроса';
                        statusText.className = 'status-text status-error';
                    }
                }

            } catch (error) {
                console.error('Error:', error);
                pre.textContent = ' Ошибка: ' + error.message + '\\n\\nПроверьте, запущен ли сервер.';
                if (statusText) {
                    statusText.textContent = ' Ошибка соединения';
                    statusText.className = 'status-text status-error';
                }
            } finally {
                if (button) {
                    button.disabled = false;
                    button.innerHTML = method === 'GET' ? 'Выполнить' : 'Обновить';
                }
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            console.log('Page loaded, loading config...');
        });
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)


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

    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Скачивание BDU файла</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                text-align: center;
                padding: 50px;
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                min-height: 100vh;
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                max-width: 500px;
                width: 100%;
            }}
            .icon {{
                font-size: 60px;
                margin-bottom: 20px;
            }}
            .spinner {{
                border: 4px solid #f3f3f3;
                border-top: 4px solid #f5576c;
                border-radius: 50%;
                width: 50px;
                height: 50px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
            .btn {{
                display: inline-block;
                padding: 12px 30px;
                background: #f5576c;
                color: white;
                text-decoration: none;
                border-radius: 8px;
                margin-top: 20px;
                transition: all 0.3s;
            }}
            .btn:hover {{
                background: #d32f2f;
                transform: scale(1.05);
            }}
            .status {{
                margin-top: 15px;
                padding: 10px;
                background: #f0f0f0;
                border-radius: 8px;
                font-size: 14px;
                color: #333;
            }}
        </style>
        <script>
            window.onload = function() {{
                setTimeout(function() {{
                    var link = document.createElement('a');
                    link.href = '{update_url_bdu}';
                    link.target = '_blank';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    
                    document.getElementById('status').innerHTML = '✅ Скачивание началось! Файл сохраняется в папку "Загрузки"';
                    document.getElementById('status').style.background = '#d4edda';
                    document.getElementById('status').style.color = '#155724';
                }}, 1000);
            }};
            
            function downloadAgain() {{
                var link = document.createElement('a');
                link.href = '{update_url_bdu}';
                link.target = '_blank';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <div class="icon">📥</div>
            <h2>Скачивание BDU файла</h2>
            <div class="spinner"></div>
            <p>Идет подготовка к скачиванию...</p>
            <div id="status" class="status">⏳ Подготовка файла...</div>
            <br>
            <button onclick="downloadAgain()" class="btn">⬇️ Скачать еще раз</button>
            <br><br>
            <a href="#" onclick="window.close(); return false;" style="color: #667eea; text-decoration: none;">
                ← Вернуться назад
            </a>
            <p style="margin-top: 20px; font-size: 12px; color: #999;">
                Если скачивание не началось автоматически, нажмите кнопку выше.
            </p>
        </div>
    </body>
    </html>
    """
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
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Скачивание CVE файла</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                text-align: center;
                padding: 50px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                margin: 0;
                display: flex;
                justify-content: center;
                align-items: center;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                max-width: 500px;
                width: 100%;
            }}
            .icon {{
                font-size: 60px;
                margin-bottom: 20px;
            }}
            .spinner {{
                border: 4px solid #f3f3f3;
                border-top: 4px solid #667eea;
                border-radius: 50%;
                width: 50px;
                height: 50px;
                animation: spin 1s linear infinite;
                margin: 20px auto;
            }}
            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}
            .btn {{
                display: inline-block;
                padding: 12px 30px;
                background: #667eea;
                color: white;
                text-decoration: none;
                border-radius: 8px;
                margin-top: 20px;
                transition: all 0.3s;
                border: none;
                cursor: pointer;
                font-size: 16px;
            }}
            .btn:hover {{
                background: #764ba2;
                transform: scale(1.05);
            }}
            .status {{
                margin-top: 15px;
                padding: 10px;
                background: #f0f0f0;
                border-radius: 8px;
                font-size: 14px;
                color: #333;
            }}
            .success {{
                background: #d4edda !important;
                color: #155724 !important;
            }}
        </style>
        <script>
            window.onload = function() {{
                setTimeout(function() {{
                    var link = document.createElement('a');
                    link.href = '{update_url_cve}';
                    link.target = '_blank';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    
                    var statusEl = document.getElementById('status');
                    statusEl.innerHTML = '✅ Скачивание началось! Файл сохраняется в папку "Загрузки"';
                    statusEl.className = 'status success';
                }}, 1000);
            }};
            
            function downloadAgain() {{
                var link = document.createElement('a');
                link.href = '{update_url_cve}';
                link.target = '_blank';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <div class="icon">📥</div>
            <h2>Скачивание CVE файла</h2>
            <div class="spinner"></div>
            <p>Идет подготовка к скачиванию...</p>
            <div id="status" class="status">⏳ Подготовка файла...</div>
            <br>
            <button onclick="downloadAgain()" class="btn">⬇️ Скачать еще раз</button>
            <br><br>
            <a href="#" onclick="window.close(); return false;" style="color: #667eea; text-decoration: none;">
                ← Вернуться назад
            </a>
            <p style="margin-top: 20px; font-size: 12px; color: #999;">
                Если скачивание не началось автоматически, нажмите кнопку выше.
            </p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/rep", summary="Получить файлы CVE и БДУ из Интернета", tags=["CVE"])
async def download_base():
    """
    Скачивает существующую базу данных CVE и BDU в сжатых архивах
    """
    config = await get_config_from_redis()
    update_url_cve = config["update_url_cve"]
    update_url_bdu = config["update_url_bdu"]
    if not update_url_cve or not update_url_bdu:
        return {
            "status": False,
            "message": "URL для обновления не настроен. Проверьте конфигурацию."
        }
    
    results = []
    
    try:
        result = await update_cve_in_mongo(update_url_cve, use_browser=False)
        if isinstance(result, dict):
            results.append(result)
        else:
            results.append({
                "status": True,
                "message": f"Файл CVE успешно скачан и обработан"
            })
    except Exception as e:
        results.append({
            "status": False,
            "message": f"Ошибка скачивания CVE: {str(e)}"
        })
    
    try:
        result = await update_bdu_in_mongo(update_url_bdu, use_browser=False)
        if isinstance(result, dict):
            results.append(result)
        else:
            results.append({
                "status": True,
                "message": f"Файл BDU успешно скачан и обработан"
            })
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