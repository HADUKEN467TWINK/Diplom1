import os
import json
import redis.asyncio as redis
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
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


# ==================== HTML СТРАНИЦА ====================
@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Config Manager</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <script src="https://unpkg.com/htmx.org@1.9.10"></script>
        <style>
            body { background: #f0f2f5; padding: 20px 0; }
            .container { max-width: 1200px; }
            .card { border-radius: 12px; box-shadow: 0 2px 15px rgba(0,0,0,0.08); border: none; margin-bottom: 20px; }
            .card-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 12px 12px 0 0 !important; padding: 15px 20px; }
            .card-header h5 { margin: 0; font-weight: 600; }
            .config-value { background: #f8f9fa; padding: 8px 12px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 13px; word-break: break-all; border-left: 3px solid #667eea; }
            .config-label { font-weight: 600; color: #6c757d; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
            .btn-gradient { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; }
            .btn-gradient:hover { color: white; opacity: 0.9; }
            .htmx-indicator { display: none; }
            .htmx-request .htmx-indicator { display: inline-block; }
            .htmx-request .btn-text { display: none; }
            .spinner-sm {
                display: none;
                width: 1rem;
                height: 1rem;
                border: 0.15em solid currentColor;
                border-right-color: transparent;
                border-radius: 50%;
                animation: spinner-border 0.75s linear infinite;
            }
            .loading .spinner-sm { display: inline-block; }
            .loading .btn-icon { display: none; }
            @keyframes spinner-border { to { transform: rotate(360deg); } }
            .empty-state { text-align: center; padding: 40px 20px; color: #6c757d; }
            .empty-state i { font-size: 3rem; margin-bottom: 15px; color: #dee2e6; }
            .fade-in { animation: fadeIn 0.3s ease; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
            .status-success { background: #d4edda; color: #155724; }
            .status-error { background: #f8d7da; color: #721c24; }
            .status-info { background: #d1ecf1; color: #0c5460; }
        </style>
    </head>
    <body>
        <div class="container">
            <!-- Заголовок -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <div>
                                <i class="fas fa-cog me-2"></i>
                                <h2 class="d-inline-block mb-0">Config Manager</h2>
                            </div>
                            <div>
                                <span class="badge bg-light text-dark" id="redisStatus">
                                    <span class="redis-status online"></span>
                                    Redis: <span id="redisHost">my-redis:6379</span>
                                </span>
                            </div>
                        </div>
                        <div class="card-body">
                            <p class="mb-0 text-muted">
                                <i class="fas fa-database me-2"></i>
                                Управление настройками в <strong>Redis</strong>
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Основной контент -->
            <div class="row">
                <!-- Левая колонка: Отображение настроек -->
                <div class="col-lg-6">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5><i class="fas fa-eye me-2"></i> Текущие настройки</h5>
                        </div>
                        <div class="card-body" id="configDisplay">
                            <div class="text-center py-4">
                                <div class="spinner-border text-primary" role="status">
                                    <span class="visually-hidden">Загрузка...</span>
                                </div>
                                <p class="mt-2 text-muted">Загрузка настроек...</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Правая колонка: Форма редактирования -->
                <div class="col-lg-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-edit me-2"></i> Редактировать</h5>
                        </div>
                        <div class="card-body">
                            <form id="configForm">
                                <div class="mb-3">
                                    <label class="form-label">MongoDB URL</label>
                                    <input type="text" class="form-control" id="mongodb_url" placeholder="mongodb://mongodb:27017/">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">CVE URL</label>
                                    <input type="url" class="form-control" id="update_url_cve" placeholder="https://example.com/CVE.zip">
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">BDU URL</label>
                                    <input type="url" class="form-control" id="update_url_bdu" placeholder="https://example.com/BDU.xml">
                                </div>
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label class="form-label">Имя файла CVE</label>
                                            <input type="text" class="form-control" id="filename_cve" placeholder="CVE_start.zip">
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="mb-3">
                                            <label class="form-label">Имя файла BDU</label>
                                            <input type="text" class="form-control" id="filename_bdu" placeholder="bdu_test_12.xml">
                                        </div>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label class="form-label">Имя базы данных</label>
                                    <input type="text" class="form-control" id="name_base" placeholder="bd">
                                </div>
                                <div class="d-flex gap-2">
                                    <button type="submit" class="btn btn-gradient flex-grow-1" id="saveBtn">
                                        <span class="btn-icon"><i class="fas fa-save me-2"></i>Сохранить</span>
                                        <span class="spinner-sm"></span>
                                        <span id="saveIndicator" class="htmx-indicator">Сохранение...</span>
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Кнопки управления -->
            <div class="row mt-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-tools me-2"></i> Управление</h5>
                        </div>
                        <div class="card-body">
                            <div class="d-flex gap-2 flex-wrap">
                                <button class="btn btn-danger" id="clearAllBtn">
                                    <i class="fas fa-trash me-2"></i>Очистить всё
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Статус -->
            <div class="row mt-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-info-circle me-2"></i> Статус</h5>
                        </div>
                        <div class="card-body" id="statusContainer">
                            <div class="alert alert-info mb-0">
                                <i class="fas fa-info-circle me-2"></i> Готов к работе
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // ===== Загрузка настроек =====
        async function loadConfig() {
            try {
                const response = await fetch('/api/config');
                if (!response.ok) throw new Error('Ошибка загрузки');
                const config = await response.json();
                displayConfig(config);
                fillForm(config);
                showStatus('Настройки загружены', 'info');
            } catch (error) {
                showStatus('Ошибка загрузки: ' + error.message, 'error');
            }
        }

        // ===== Отображение настроек =====
        function displayConfig(config) {
            const container = document.getElementById('configDisplay');
            if (!config || Object.keys(config).length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-database"></i>
                        <h5>Нет данных</h5>
                        <p class="text-muted">Настройки не найдены в Redis</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = `
                <div class="mb-3">
                    <div class="config-label"><i class="fas fa-database me-1"></i> MongoDB URL</div>
                    <div class="config-value">${config.mongodb_url || '—'}</div>
                </div>
                <div class="mb-3">
                    <div class="config-label"><i class="fas fa-cloud me-1"></i> CVE URL</div>
                    <div class="config-value text-primary">${config.update_url_cve || '—'}</div>
                </div>
                <div class="mb-3">
                    <div class="config-label"><i class="fas fa-cloud me-1"></i> BDU URL</div>
                    <div class="config-value text-info">${config.update_url_bdu || '—'}</div>
                </div>
                <div class="row">
                    <div class="col-6">
                        <div class="mb-2">
                            <div class="config-label"><i class="fas fa-file-archive me-1"></i> Файл CVE</div>
                            <div class="config-value">${config.filename_cve || '—'}</div>
                        </div>
                    </div>
                    <div class="col-6">
                        <div class="mb-2">
                            <div class="config-label"><i class="fas fa-file-code me-1"></i> Файл BDU</div>
                            <div class="config-value">${config.filename_bdu || '—'}</div>
                        </div>
                    </div>
                </div>
                <div class="mb-0">
                    <div class="config-label"><i class="fas fa-tag me-1"></i> База данных</div>
                    <div class="config-value fw-bold">${config.name_base || '—'}</div>
                </div>
                <hr>
                <div class="mt-2">
                    <small class="text-muted">RAW JSON:</small>
                    <pre style="background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 6px; font-size: 11px; max-height: 100px; overflow: auto; margin: 5px 0 0 0;">${JSON.stringify(config, null, 2)}</pre>
                </div>
            `;
        }

        // ===== Заполнение формы =====
        function fillForm(config) {
            document.getElementById('mongodb_url').value = config.mongodb_url || '';
            document.getElementById('update_url_cve').value = config.update_url_cve || '';
            document.getElementById('update_url_bdu').value = config.update_url_bdu || '';
            document.getElementById('filename_cve').value = config.filename_cve || '';
            document.getElementById('filename_bdu').value = config.filename_bdu || '';
            document.getElementById('name_base').value = config.name_base || '';
        }

        // ===== Сохранение настроек =====
        async function saveConfig() {
            const data = {
                mongodb_url: document.getElementById('mongodb_url').value,
                update_url_cve: document.getElementById('update_url_cve').value,
                update_url_bdu: document.getElementById('update_url_bdu').value,
                filename_cve: document.getElementById('filename_cve').value,
                filename_bdu: document.getElementById('filename_bdu').value,
                name_base: document.getElementById('name_base').value
            };

            const btn = document.getElementById('saveBtn');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Сохранение...';

            try {
                const response = await fetch('/api/config', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.detail || 'Ошибка сохранения');
                }
                const result = await response.json();
                displayConfig(result);
                showStatus('✅ Настройки сохранены!', 'success');
            } catch (error) {
                showStatus('❌ Ошибка: ' + error.message, 'error');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<span class="btn-icon"><i class="fas fa-save me-2"></i>Сохранить</span>';
            }
        }

        // ===== Очистка всех настроек =====
        async function clearAll() {
            if (!confirm('⚠️ Удалить все настройки из Redis?')) return;
            
            const keys = ['mongodb_url', 'filename_cve', 'filename_bdu', 'update_url_cve', 'update_url_bdu', 'name_base'];
            let successCount = 0;
            
            try {
                for (const key of keys) {
                    const response = await fetch(`/api/config/${key}`, { method: 'DELETE' });
                    if (response.ok) successCount++;
                }
                
                if (successCount === keys.length) {
                    showStatus('✅ Все настройки удалены!', 'success');
                } else {
                    showStatus(`⚠️ Удалено ${successCount} из ${keys.length} настроек`, 'info');
                }
                
                // Обновляем страницу
                await loadConfig();
                document.getElementById('configForm').reset();
                
            } catch (error) {
                showStatus('❌ Ошибка: ' + error.message, 'error');
            }
        }

        // ===== Статус =====
        function showStatus(message, type = 'info') {
            const container = document.getElementById('statusContainer');
            const alertClass = type === 'success' ? 'alert-success' :
                            type === 'error' ? 'alert-danger' : 'alert-info';
            const icon = type === 'success' ? 'fa-check-circle' :
                        type === 'error' ? 'fa-exclamation-triangle' : 'fa-info-circle';
            container.innerHTML = `
                <div class="alert ${alertClass} mb-0 fade-in">
                    <i class="fas ${icon} me-2"></i> ${message}
                </div>
            `;
        }

        // ===== Обработчики событий =====
        document.addEventListener('DOMContentLoaded', function() {
            // Загружаем настройки
            loadConfig();

            // Форма сохранения
            document.getElementById('configForm').addEventListener('submit', function(e) {
                e.preventDefault();
                saveConfig();
            });

            // Кнопка "Очистить всё"
            document.getElementById('clearAllBtn').addEventListener('click', clearAll);
        });
    </script>
    </body>
    </html>
    """


# ==================== ЗАПУСК ====================
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8085, reload=True)