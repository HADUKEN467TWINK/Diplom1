import os
import json
import redis.asyncio as redis
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uvicorn
from datetime import datetime
import asyncio
from mcp.server.fastmcp import FastMCP

app = FastAPI(title="Viewer_CVE")
mcp = FastMCP("MCP Server")

# CORS
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
    """Инициализация MongoDB с данными из Redis"""
    await redis_client.ping()
    mongodb_url = await redis_client.hget("my_config", "mongodb_url")
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
    return """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Просмотр CVE</title>
            <!-- Font Awesome (иконки) -->
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    background: #f4f7fb;
                    font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
                    padding: 30px 20px;
                    color: #1e293b;
                }
                .container {
                    max-width: 1400px;
                    margin: 0 auto;
                }

                /* шапка */
                .header {
                    display: flex;
                    flex-wrap: wrap;
                    align-items: center;
                    justify-content: space-between;
                    margin-bottom: 30px;
                    background: white;
                    padding: 20px 28px;
                    border-radius: 24px;
                    box-shadow: 0 8px 20px rgba(0,0,0,0.03);
                    border: 1px solid #e9edf2;
                }
                .header h1 {
                    font-size: 26px;
                    font-weight: 600;
                    letter-spacing: -0.3px;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }
                .header h1 i {
                    color: #2563eb;
                    font-size: 28px;
                }
                .badge {
                    background: #eef2ff;
                    color: #2563eb;
                    font-size: 14px;
                    font-weight: 500;
                    padding: 4px 14px;
                    border-radius: 40px;
                    margin-left: 8px;
                }
                .config-status {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    background: #f8fafc;
                    padding: 6px 16px 6px 12px;
                    border-radius: 40px;
                    font-size: 14px;
                    border: 1px solid #e2e8f0;
                }
                .config-status .dot {
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    display: inline-block;
                }
                .dot.green { background: #22c55e; }
                .dot.red { background: #ef4444; }

                /* панель фильтров */
                .filter-panel {
                    background: white;
                    border-radius: 20px;
                    padding: 20px 24px;
                    margin-bottom: 30px;
                    border: 1px solid #e9edf2;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.02);
                    display: flex;
                    flex-wrap: wrap;
                    align-items: center;
                    gap: 16px 24px;
                }
                .filter-panel .field {
                    display: flex;
                    align-items: center;
                    gap: 8px;
                    flex: 1 1 220px;
                }
                .filter-panel .field i {
                    color: #64748b;
                    width: 20px;
                    font-size: 16px;
                }
                .filter-panel input,
                .filter-panel select {
                    padding: 10px 14px;
                    border: 1px solid #d1d9e6;
                    border-radius: 40px;
                    font-size: 14px;
                    background: white;
                    width: 100%;
                    transition: 0.15s;
                    outline: none;
                }
                .filter-panel input:focus,
                .filter-panel select:focus {
                    border-color: #2563eb;
                    box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
                }
                .filter-panel .actions {
                    display: flex;
                    gap: 10px;
                    margin-left: auto;
                }
                .btn {
                    background: white;
                    border: 1px solid #d1d9e6;
                    padding: 10px 22px;
                    border-radius: 40px;
                    font-weight: 500;
                    font-size: 14px;
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    cursor: pointer;
                    transition: 0.15s;
                    color: #1e293b;
                }
                .btn-primary {
                    background: #2563eb;
                    border: 1px solid #2563eb;
                    color: white;
                }
                .btn-primary:hover {
                    background: #1d4ed8;
                    border-color: #1d4ed8;
                }
                .btn-outline {
                    background: transparent;
                }
                .btn-outline:hover {
                    background: #f1f5f9;
                }
                .btn i { font-size: 14px; }

                /* таблица */
                .table-wrapper {
                    background: white;
                    border-radius: 24px;
                    border: 1px solid #e9edf2;
                    overflow-x: auto;
                    box-shadow: 0 8px 24px rgba(0,0,0,0.02);
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 14px;
                    min-width: 700px;
                }
                thead {
                    background: #f8fafc;
                    border-bottom: 1px solid #e2e8f0;
                }
                th {
                    text-align: left;
                    padding: 16px 18px;
                    font-weight: 600;
                    color: #475569;
                    letter-spacing: 0.3px;
                    white-space: nowrap;
                }
                td {
                    padding: 14px 18px;
                    border-bottom: 1px solid #f1f5f9;
                    vertical-align: middle;
                }
                tr:last-child td {
                    border-bottom: none;
                }
                tr:hover td {
                    background: #fafcff;
                }
                .cve-id {
                    font-weight: 600;
                    color: #1e293b;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 13px;
                    background: #f1f4f9;
                    padding: 2px 12px;
                    border-radius: 40px;
                    display: inline-block;
                }
                .severity-badge {
                    display: inline-block;
                    padding: 2px 14px;
                    border-radius: 40px;
                    font-weight: 600;
                    font-size: 12px;
                    letter-spacing: 0.3px;
                    text-transform: uppercase;
                    background: #e2e8f0;
                    color: #334155;
                }
                .severity-critical { background: #fecaca; color: #b91c1c; }
                .severity-high    { background: #fdba74; color: #9a3412; }
                .severity-medium  { background: #fde047; color: #854d0e; }
                .severity-low     { background: #bbf7d0; color: #166534; }
                .severity-none    { background: #e2e8f0; color: #475569; }

                .desc-preview {
                    max-width: 280px;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    color: #334155;
                }
                .status-badge {
                    font-size: 12px;
                    background: #eef2ff;
                    padding: 2px 12px;
                    border-radius: 40px;
                    color: #2563eb;
                }
                .empty-state {
                    text-align: center;
                    padding: 60px 20px;
                    color: #94a3b8;
                }
                .empty-state i {
                    font-size: 48px;
                    margin-bottom: 16px;
                    opacity: 0.3;
                }
                .pagination {
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    gap: 16px;
                    padding: 20px 0 10px;
                    font-size: 14px;
                    color: #475569;
                }
                .pagination button {
                    background: white;
                    border: 1px solid #d1d9e6;
                    padding: 6px 18px;
                    border-radius: 40px;
                    cursor: pointer;
                    font-weight: 500;
                    transition: 0.1s;
                }
                .pagination button:hover:not(:disabled) {
                    background: #f1f5f9;
                }
                .pagination button:disabled {
                    opacity: 0.4;
                    cursor: not-allowed;
                }
                .spinner {
                    text-align: center;
                    padding: 40px 0;
                    color: #2563eb;
                }
                .footer-meta {
                    margin-top: 16px;
                    text-align: right;
                    font-size: 13px;
                    color: #94a3b8;
                    padding-right: 8px;
                }

                @media (max-width: 700px) {
                    .header { flex-direction: column; align-items: start; gap: 12px; }
                    .filter-panel .actions { margin-left: 0; width: 100%; }
                    .filter-panel .actions .btn { flex: 1; justify-content: center; }
                }
            </style>
        </head>
        <body>
        <div class="container">
            <!-- Шапка -->
            <div class="header">
                <h1>
                    <i class="fas fa-shield-alt"></i> CVE Explorer
                    <span class="badge">v1</span>
                </h1>
                <div class="config-status">
                    <span class="dot green" id="statusDot"></span>
                    <span id="configStatusText">Подключено</span>
                    <i class="fas fa-database" style="margin-left: 6px; color: #64748b;"></i>
                    <span id="dbName" style="font-weight: 500;">—</span>
                </div>
            </div>

            <!-- Фильтры -->
            <div class="filter-panel">
                <div class="field">
                    <i class="fas fa-search"></i>
                    <input type="text" id="searchInput" placeholder="CVE ID или описание..." value="">
                </div>
                <div class="field">
                    <i class="fas fa-tag"></i>
                    <select id="severityFilter">
                        <option value="">Все уровни</option>
                        <option value="CRITICAL">Критический</option>
                        <option value="HIGH">Высокий</option>
                        <option value="MEDIUM">Средний</option>
                        <option value="LOW">Низкий</option>
                        <option value="NONE">Нет</option>
                    </select>
                </div>
                <div class="actions">
                    <button class="btn btn-primary" id="applyFilterBtn"><i class="fas fa-filter"></i> Применить</button>
                    <button class="btn btn-outline" id="resetFilterBtn"><i class="fas fa-undo-alt"></i> Сброс</button>
                </div>
            </div>

            <!-- Таблица -->
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Описание</th>
                            <th>Уровень</th>
                            <th>Дата публикации</th>
                            <th>Статус</th>
                        </tr>
                    </thead>
                    <tbody id="cveTableBody">
                        <tr><td colspan="5" class="empty-state">
                            <i class="fas fa-cloud-download-alt"></i>
                            <div>Загрузка данных...</div>
                        </td></tr>
                    </tbody>
                </table>
            </div>

            <!-- Пагинация -->
            <div class="pagination">
                <button id="prevPageBtn" disabled><i class="fas fa-chevron-left"></i> Назад</button>
                <span id="pageInfo">Страница 1</span>
                <button id="nextPageBtn">Вперед <i class="fas fa-chevron-right"></i></button>
            </div>
            <div class="footer-meta" id="totalCountInfo">Всего записей: —</div>
        </div>

        <script>
            // ---------- Конфигурация ----------
            const API_BASE = window.location.origin;

            // Состояние
            let currentPage = 1;
            const pageSize = 20;
            let totalRecords = 0;
            let currentFilter = {
                search: '',
                severity: ''
            };

            // DOM ссылки
            const tbody = document.getElementById('cveTableBody');
            const searchInput = document.getElementById('searchInput');
            const severityFilter = document.getElementById('severityFilter');
            const applyBtn = document.getElementById('applyFilterBtn');
            const resetBtn = document.getElementById('resetFilterBtn');
            const prevBtn = document.getElementById('prevPageBtn');
            const nextBtn = document.getElementById('nextPageBtn');
            const pageInfo = document.getElementById('pageInfo');
            const totalCountInfo = document.getElementById('totalCountInfo');
            const dbNameSpan = document.getElementById('dbName');

            // ---------- Вспомогательные функции ----------
            function getSeverityClass(severity) {
                if (!severity) return 'severity-none';
                const s = severity.toUpperCase();
                if (s.includes('CRITICAL')) return 'severity-critical';
                if (s.includes('HIGH')) return 'severity-high';
                if (s.includes('MEDIUM')) return 'severity-medium';
                if (s.includes('LOW')) return 'severity-low';
                return 'severity-none';
            }

            function formatDate(dateStr) {
                if (!dateStr) return '—';
                try {
                    const d = new Date(dateStr);
                    return d.toLocaleDateString('ru-RU', { year: 'numeric', month: 'short', day: 'numeric' });
                } catch { return dateStr; }
            }

            // Получить конфиг из /api/config
            async function fetchConfig() {
                try {
                    const resp = await fetch(`${API_BASE}/api/config`);
                    if (!resp.ok) throw new Error('Не удалось получить конфиг');
                    const data = await resp.json();
                    if (data.status && data.config && data.config.name_base) {
                        dbNameSpan.textContent = data.config.name_base;
                    } else {
                        dbNameSpan.textContent = 'не задана';
                    }
                } catch (e) {
                    console.warn('Ошибка получения конфига:', e);
                    dbNameSpan.textContent = 'ошибка';
                    document.getElementById('statusDot').className = 'dot red';
                    document.getElementById('configStatusText').textContent = 'Ошибка';
                }
            }

            // Загрузка CVE из API
            async function fetchCVE(page = 1) {
                const search = currentFilter.search.trim();
                const severity = currentFilter.severity;

                const params = new URLSearchParams({
                    page: page,
                    limit: pageSize
                });
                if (search) params.append('search', search);
                if (severity) params.append('severity', severity);

                try {
                    const resp = await fetch(`${API_BASE}/api/cves?${params}`);
                    if (!resp.ok) throw new Error('Ошибка загрузки CVE');
                    const data = await resp.json();
                    totalRecords = data.total || 0;
                    return data;
                } catch (error) {
                    console.error('Ошибка загрузки CVE:', error);
                    throw error;
                }
            }

            // ---------- Отрисовка таблицы ----------
            function renderTable(data) {
                if (!data || data.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">
                        <i class="fas fa-inbox"></i>
                        <div>Уязвимости не найдены</div>
                    </td></tr>`;
                    totalCountInfo.textContent = `Всего записей: 0`;
                    return;
                }

                let html = '';
                data.forEach(item => {
                    const cveId = item.cveMetadata?.cveId || item._id || '—';
                    const desc = item.containers?.cna?.descriptions?.[0]?.value || 'Нет описания';
                    const severity = item.severity_info?.severity || 'NONE';
                    const score = item.severity_info?.score || 0;
                    const version = item.severity_info?.version || '';
                    const severityClass = getSeverityClass(severity);
                    const published = formatDate(item.cveMetadata?.datePublished);
                    const status = item.cveMetadata?.state || '—';

                    html += `<tr>
                        <td><span class="cve-id">${cveId}</span></td>
                        <td><div class="desc-preview" title="${desc.replace(/"/g, '&quot;')}">${desc}</div></td>
                        <td>
                            <span class="severity-badge ${severityClass}">${severity}</span>
                            ${score ? `<span style="font-size:11px;color:#64748b;display:block;">Score: ${score}</span>` : ''}
                        </td>
                        <td>${published}</td>
                        <td><span class="status-badge">${status}</span></td>
                    </tr>`;
                });
                tbody.innerHTML = html;
                totalCountInfo.textContent = `Всего записей: ${totalRecords}`;
            }

            // ---------- Обновить страницу ----------
            async function refreshTable() {
                tbody.innerHTML = `<tr><td colspan="5" class="empty-state">
                    <i class="fas fa-spinner fa-pulse"></i>
                    <div>Загрузка...</div>
                </td></tr>`;

                try {
                    const result = await fetchCVE(currentPage);
                    renderTable(result.items);
                    const totalPages = Math.ceil(result.total / pageSize) || 1;
                    pageInfo.textContent = `Страница ${currentPage} из ${totalPages}`;
                    prevBtn.disabled = currentPage <= 1;
                    nextBtn.disabled = currentPage >= totalPages;
                } catch (error) {
                    console.error('Ошибка загрузки:', error);
                    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">
                        <i class="fas fa-exclamation-triangle" style="color:#ef4444;"></i>
                        <div>Ошибка загрузки данных</div>
                    </td></tr>`;
                }
            }

            // ---------- Обработчики ----------
            applyBtn.addEventListener('click', () => {
                currentFilter.search = searchInput.value;
                currentFilter.severity = severityFilter.value;
                currentPage = 1;
                refreshTable();
            });

            resetBtn.addEventListener('click', () => {
                searchInput.value = '';
                severityFilter.value = '';
                currentFilter.search = '';
                currentFilter.severity = '';
                currentPage = 1;
                refreshTable();
            });

            prevBtn.addEventListener('click', () => {
                if (currentPage > 1) {
                    currentPage--;
                    refreshTable();
                }
            });

            nextBtn.addEventListener('click', () => {
                currentPage++;
                refreshTable();
            });

            // ---------- Инициализация ----------
            async function init() {
                await fetchConfig();
                await refreshTable();
            }

            init();
        </script>
        </body>
        </html>
    """

@app.get("/api/get_severity_score/{baseScore}")
def get_severity_from_score(baseScore):
    """Определяет уровень серьезности на основе baseScore"""
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

@app.get("/api/get_cve_severity/{cve_item}")
def get_cve_severity(cve_item):
    """
    Извлекает максимальный baseScore из всех доступных версий CVSS
    Ищет как в cna, так и в adp метриках
    """
    all_scores = []
    priority_versions = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']
    
    # Проверяем в cna метриках
    metrics = cve_item.get('containers', {}).get('cna', {}).get('metrics', [])
    for metric in metrics:
        for version in priority_versions:
            if version in metric:
                cvss_data = metric[version]
                base_score = cvss_data.get('baseScore')
                if base_score is not None:
                    all_scores.append({
                        'score': float(base_score),
                        'version': version.replace('cvss', 'CVSS ').replace('_', '.'),
                        'source': 'cna'
                    })
    
    # Проверяем в adp метриках
    adp_metrics = cve_item.get('containers', {}).get('adp', [])
    for adp_item in adp_metrics:
        metrics = adp_item.get('metrics', [])
        for metric in metrics:
            for version in priority_versions:
                if version in metric:
                    cvss_data = metric[version]
                    base_score = cvss_data.get('baseScore')
                    if base_score is not None:
                        all_scores.append({
                            'score': float(base_score),
                            'version': version.replace('cvss', 'CVSS ').replace('_', '.'),
                            'source': 'adp'
                        })
    
    # Если есть оценки, берем максимальную
    if all_scores:
        max_score_item = max(all_scores, key=lambda x: x['score'])
        return {
            'score': max_score_item['score'],
            'severity': get_severity_from_score(max_score_item['score']),
            'version': max_score_item['version'],
            'source': max_score_item['source'],
            'all_scores': all_scores  # опционально: все найденные оценки
        }
    
    return {
        'score': None,
        'severity': 'UNKNOWN',
        'version': None,
        'source': None,
        'all_scores': []
    }

@app.get("/api/config")
async def get_config():
    """Получить конфигурацию"""
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
    page: int = Query(1, ge=1, description="Номер страницы"),
    limit: int = Query(20, ge=1, le=100, description="Количество записей на странице"),
    search: Optional[str] = Query(None, description="Поиск по ID или описанию"),
    severity: Optional[str] = Query(None, description="Фильтр по уровню опасности")
):
    """
    Получить список CVE из MongoDB с пагинацией и фильтрацией
    """
    try:
        if base is None:
            return JSONResponse(
                status_code=503,
                content={
                    "status": False,
                    "message": "MongoDB не доступна",
                    "items": [],
                    "total": 0,
                    "page": page,
                    "pageSize": limit
                }
            )

        collection = base["CVE"]
    
        pipeline = []
        
        if search and search.strip():
            search_term = search.strip()
            pipeline.append({
                "$match": {
                    "$or": [
                        {"cveMetadata.cveId": {"$regex": search_term, "$options": "i"}},
                        {"containers.cna.descriptions.value": {"$regex": search_term, "$options": "i"}}
                    ]
                }
            })
        
        pipeline.append({
            "$addFields": {
                "max_cvss_score": {
                    "$max": {
                        "$concatArrays": [
                            {
                                "$map": {
                                    "input": "$containers.cna.metrics",
                                    "as": "metric",
                                    "in": {
                                        "$max": [
                                            "$$metric.cvssV4_0.baseScore",
                                            "$$metric.cvssV3_1.baseScore",
                                            "$$metric.cvssV3_0.baseScore",
                                            "$$metric.cvssV2_0.baseScore"
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
                                                "$map": {
                                                    "input": "$$this.metrics",
                                                    "as": "adp_metric",
                                                    "in": {
                                                        "$max": [
                                                            "$$adp_metric.cvssV4_0.baseScore",
                                                            "$$adp_metric.cvssV3_1.baseScore",
                                                            "$$adp_metric.cvssV3_0.baseScore",
                                                            "$$adp_metric.cvssV2_0.baseScore"
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
            }
        })

        if severity and severity.strip():
            severity_upper = severity.upper()
            severity_ranges = {
                'NONE': (0.0, 0.0),
                'LOW': (0.1, 3.9),
                'MEDIUM': (4.0, 6.9),
                'HIGH': (7.0, 8.9),
                'CRITICAL': (9.0, 10.0),
                'UNKNOWN': (None, None)
            }
            
            if severity_upper in severity_ranges:
                min_score, max_score = severity_ranges[severity_upper]
                if severity_upper == 'NONE':
                    pipeline.append({
                        "$match": {"max_cvss_score": None}
                    })
                elif min_score == max_score:
                    pipeline.append({
                        "$match": {"max_cvss_score": min_score}
                    })
                else:
                    pipeline.append({
                        "$match": {
                            "max_cvss_score": {"$gte": min_score, "$lte": max_score}
                        }
                    })
        
        pipeline.append({
            "$addFields": {
                "severity_info": {
                    "score": "$max_cvss_score",
                    "severity": {
                        "$switch": {
                            "branches": [
                                {"case": {"$eq": ["$max_cvss_score", None]}, "then": "UNKNOWN"},
                                {"case": {"$eq": ["$max_cvss_score", 0.0]}, "then": "NONE"},
                                {"case": {"$lt": ["$max_cvss_score", 4.0]}, "then": "LOW"},
                                {"case": {"$lt": ["$max_cvss_score", 7.0]}, "then": "MEDIUM"},
                                {"case": {"$lt": ["$max_cvss_score", 9.0]}, "then": "HIGH"},
                            ],
                            "default": "CRITICAL"
                        }
                    }
                }
            }
        })
        
        pipeline.append({"$skip": (page - 1) * limit})
        pipeline.append({"$limit": limit})
        
        cursor = collection.aggregate(pipeline)
        items = await cursor.to_list(length=limit)
        
        count_pipeline = pipeline.copy()
        count_pipeline = [stage for stage in count_pipeline if "$skip" not in stage and "$limit" not in stage]
        count_pipeline.append({"$count": "total"})
        
        count_cursor = collection.aggregate(count_pipeline)
        count_result = await count_cursor.to_list(length=1)
        total = count_result[0]["total"] if count_result else 0
        
        for item in items:
            if "_id" in item:
                item["_id"] = str(item["_id"])
        
        return {
            "status": True,
            "items": items,
            "total": total,
            "page": page,
            "pageSize": limit,
            "totalPages": (total + limit - 1) // limit if total > 0 else 1
        }
        
    except Exception as e:
        print(f"❌ Ошибка получения CVE: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "status": False,
                "message": f"Ошибка получения данных: {str(e)}",
                "items": [],
                "total": 0,
                "page": page,
                "pageSize": limit
            }
        )

@app.get("/api/db-status")
async def get_db_status():
    """Проверить статус подключения к MongoDB"""
    if base is None:
        return {
            "status": False,
            "message": "MongoDB не подключена"
        }
    
    try:
        # Получаем список коллекций
        collection = base["CVE"]
        
        # Считаем количество документов в коллекции CVE
        cve_count = 0
        if "CVE" in collection:
            cve_count = await collection.count_documents({})
        
        return {
            "status": True,
            "message": "MongoDB подключена",
            "database": name_base,
            "collections": collection,
            "cve_count": cve_count
        }
    except Exception as e:
        return {
            "status": False,
            "message": f"Ошибка: {str(e)}"
        }

@mcp.tool()
@app.get("/api/cve/{cve_id}")
async def get_cve_by_id(cve_id: str):
    """Получить конкретную CVE по ID"""
    try:
        if base is None:
            return JSONResponse(
                status_code=503,
                content={"status": False, "message": "MongoDB не доступна"}
            )
        
        collection = base["CVE"]
        doc = await collection.find_one({"cveMetadata.cveId": cve_id})
        
        if not doc:
            return JSONResponse(
                status_code=404,
                content={"status": False, "message": f"CVE {cve_id} не найдена"}
            )
        
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        
        severity_info = get_cve_severity(doc)
        doc["severity_info"] = severity_info
        
        return {
            "status": True,
            "data": doc
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": False, "message": str(e)}
        )

if __name__ == "__main__":
    base, name_base = asyncio.run(init_mongo())
    uvicorn.run("main:app", host="0.0.0.0", port=8003, reload=True)