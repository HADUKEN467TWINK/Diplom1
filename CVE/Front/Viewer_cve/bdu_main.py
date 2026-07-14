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
                <title>Просмотр БДУ</title>
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
                    min-width: 900px;
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
                .bdu-id {
                    font-weight: 600;
                    color: #1e293b;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 13px;
                    background: #f1f4f9;
                    padding: 2px 12px;
                    border-radius: 40px;
                    display: inline-block;
                    white-space: nowrap;
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
                .severity-unknown { background: #e2e8f0; color: #475569; }

                .desc-cell {
                    max-width: 300px;
                    cursor: default;
                }
                .desc-preview {
                    display: -webkit-box;
                    -webkit-line-clamp: 2;
                    -webkit-box-orient: vertical;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    color: #334155;
                    line-height: 1.4;
                    word-break: break-word;
                }
                .desc-preview.expanded {
                    -webkit-line-clamp: unset;
                    display: block;
                }
                .desc-toggle {
                    color: #2563eb;
                    font-size: 12px;
                    cursor: pointer;
                    display: inline-block;
                    margin-top: 2px;
                    font-weight: 500;
                    background: none;
                    border: none;
                    padding: 2px 6px;
                }
                .desc-toggle:hover {
                    text-decoration: underline;
                    background: #f1f5f9;
                    border-radius: 4px;
                }

                .references-cell {
                    max-width: 350px;
                    min-width: 150px;
                    word-break: break-word;
                }
                .ref-link {
                    display: inline-block;
                    padding: 2px 12px;
                    margin: 2px 4px 2px 0;
                    background: #eef2ff;
                    color: #2563eb;
                    border-radius: 20px;
                    font-size: 12px;
                    text-decoration: none;
                    transition: 0.15s;
                    max-width: 100%;
                    white-space: nowrap;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    vertical-align: middle;
                }
                .ref-link:hover {
                    background: #2563eb;
                    color: white;
                }
                .ref-link i {
                    font-size: 10px;
                    margin-right: 4px;
                }

                .actions-cell {
                    white-space: nowrap;
                    text-align: center;
                    min-width: 90px;
                }
                .action-btn {
                    background: none;
                    border: none;
                    cursor: pointer;
                    padding: 6px 10px;
                    border-radius: 8px;
                    transition: 0.15s;
                    font-size: 16px;
                    color: #64748b;
                }
                .action-btn:hover {
                    background: #f1f5f9;
                    color: #2563eb;
                }
                .action-btn.json-btn {
                    color: #7c3aed;
                }
                .action-btn.json-btn:hover {
                    background: #ede9fe;
                    color: #5b21b6;
                }
                .action-btn.expand-btn {
                    color: #64748b;
                }
                .action-btn.expand-btn:hover {
                    background: #f1f5f9;
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
                    flex-wrap: wrap;
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
                .pagination-input {
                    display: flex;
                    align-items: center;
                    gap: 6px;
                    background: #f8fafc;
                    padding: 4px 8px 4px 14px;
                    border-radius: 40px;
                    border: 1px solid #e2e8f0;
                }
                .pagination-input span {
                    font-size: 13px;
                    color: #64748b;
                }
                .pagination-input input {
                    width: 50px;
                    padding: 4px 6px;
                    border: 1px solid #d1d9e6;
                    border-radius: 20px;
                    font-size: 14px;
                    text-align: center;
                    outline: none;
                    background: white;
                    transition: 0.15s;
                }
                .pagination-input input:focus {
                    border-color: #2563eb;
                    box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
                }
                .pagination-input input::-webkit-inner-spin-button {
                    -webkit-appearance: none;
                }
                .pagination-input input[type=number] {
                    -moz-appearance: textfield;
                }
                .pagination-input .btn-go {
                    background: #2563eb;
                    border: none;
                    color: white;
                    padding: 4px 14px;
                    border-radius: 30px;
                    cursor: pointer;
                    font-size: 13px;
                    transition: 0.15s;
                    display: flex;
                    align-items: center;
                    gap: 4px;
                }
                .pagination-input .btn-go:hover {
                    background: #1d4ed8;
                }
                .pagination-input .btn-go i {
                    font-size: 12px;
                }

                .footer-meta {
                    margin-top: 16px;
                    text-align: right;
                    font-size: 13px;
                    color: #94a3b8;
                    padding-right: 8px;
                }

                /* ===== МОДАЛЬНОЕ ОКНО С FIXED HEADER ===== */
                .modal-overlay {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.5);
                    z-index: 1000;
                    justify-content: center;
                    align-items: center;
                    backdrop-filter: blur(4px);
                }
                .modal-overlay.active {
                    display: flex;
                }
                .modal-box {
                    background: white;
                    max-width: 900px;
                    width: 95%;
                    max-height: 90vh;
                    border-radius: 16px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    position: relative;
                    animation: modalFadeIn 0.2s ease;
                    display: flex;
                    flex-direction: column;
                    overflow: hidden;
                }
                @keyframes modalFadeIn {
                    from { opacity: 0; transform: scale(0.95); }
                    to { opacity: 1; transform: scale(1); }
                }
                
                /* Фиксированная шапка */
                .modal-header {
                    position: sticky;
                    top: 0;
                    background: white;
                    z-index: 10;
                    padding: 20px 30px 16px 30px;
                    border-bottom: 1px solid #e9edf2;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    flex-shrink: 0;
                }
                .modal-header h3 {
                    margin: 0;
                    color: #1e293b;
                    font-size: 20px;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    padding-right: 10px;
                }
                .modal-header .modal-close {
                    font-size: 28px;
                    cursor: pointer;
                    color: #94a3b8;
                    background: none;
                    border: none;
                    transition: 0.15s;
                    line-height: 1;
                    padding: 0 8px;
                    flex-shrink: 0;
                }
                .modal-header .modal-close:hover {
                    color: #1e293b;
                    transform: scale(1.1);
                }
                
                /* Фиксированные вкладки */
                .modal-tabs-wrapper {
                    position: sticky;
                    top: 0;
                    background: white;
                    z-index: 9;
                    padding: 0 30px;
                    border-bottom: 2px solid #e9edf2;
                    flex-shrink: 0;
                }
                .modal-tabs {
                    display: flex;
                    gap: 8px;
                    padding: 12px 0;
                    flex-wrap: wrap;
                }
                .modal-tab {
                    padding: 8px 20px;
                    border-radius: 8px 8px 0 0;
                    border: none;
                    cursor: pointer;
                    font-weight: 500;
                    transition: 0.15s;
                    background: transparent;
                    color: #64748b;
                    font-size: 14px;
                }
                .modal-tab:hover {
                    background: #f1f5f9;
                }
                .modal-tab.active {
                    color: #2563eb;
                    background: #eef2ff;
                    border-bottom: 3px solid #2563eb;
                }
                
                /* Тело модального окна */
                .modal-body {
                    padding: 20px 30px 30px 30px;
                    overflow-y: auto;
                    flex: 1;
                }
                .modal-tab-content {
                    display: none;
                }
                .modal-tab-content.active {
                    display: block;
                }

                .detail-table {
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 13px;
                }
                .detail-table tr {
                    border-bottom: 1px solid #f1f5f9;
                }
                .detail-table tr:last-child {
                    border-bottom: none;
                }
                .detail-table td {
                    padding: 10px 12px;
                    vertical-align: top;
                    line-height: 1.5;
                }
                .detail-table .label {
                    font-weight: 600;
                    color: #475569;
                    white-space: nowrap;
                    min-width: 140px;
                    background: #f8fafc;
                    width: 20%;
                }
                .detail-table .value {
                    color: #1e293b;
                    word-break: break-word;
                    width: 80%;
                }
                .detail-table .value .ref-link {
                    display: inline-block;
                    margin: 2px 4px 2px 0;
                    font-size: 12px;
                }
                .detail-table .value .tag {
                    display: inline-block;
                    background: #eef2ff;
                    color: #2563eb;
                    padding: 2px 10px;
                    border-radius: 12px;
                    font-size: 11px;
                    margin: 2px 4px 2px 0;
                }
                .detail-table .value .severity-badge {
                    font-size: 11px;
                }
                .detail-table .value .cve-link {
                    display: inline-block;
                    background: #eef2ff;
                    color: #2563eb;
                    padding: 2px 12px;
                    border-radius: 12px;
                    font-size: 12px;
                    text-decoration: none;
                    margin: 2px 4px 2px 0;
                }
                .detail-table .value .cve-link:hover {
                    background: #2563eb;
                    color: white;
                }

                .json-container {
                    background: #1e1e1e;
                    border-radius: 12px;
                    padding: 0;
                    overflow: hidden;
                    margin-top: 8px;
                    max-height: calc(90vh - 350px);
                    overflow: auto;
                    position: relative;
                }
                .json-container .json-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    background: #2d2d2d;
                    padding: 10px 20px;
                    border-bottom: 1px solid #3d3d3d;
                }
                .json-container .json-header span {
                    color: #9cdcfe;
                    font-family: 'JetBrains Mono', monospace;
                    font-size: 13px;
                }
                .json-container .json-header .copy-btn {
                    background: #3d3d3d;
                    border: none;
                    color: #d4d4d4;
                    padding: 4px 14px;
                    border-radius: 6px;
                    cursor: pointer;
                    font-size: 12px;
                    transition: 0.15s;
                }
                .json-container .json-header .copy-btn:hover {
                    background: #4d4d4d;
                    color: white;
                }
                .json-container pre {
                    margin: 0;
                    padding: 20px;
                    font-family: 'JetBrains Mono', 'Consolas', monospace;
                    font-size: 12px;
                    line-height: 1.6;
                    color: #d4d4d4;
                    white-space: pre-wrap;
                    word-break: break-word;
                }

                @media (max-width: 700px) {
                    .header { flex-direction: column; align-items: start; gap: 12px; }
                    .references-cell { max-width: 150px; }
                    .ref-link { font-size: 10px; padding: 1px 8px; }
                    .desc-cell { max-width: 120px; }
                    .actions-cell { min-width: 60px; }
                    .pagination {
                        flex-direction: column;
                        gap: 10px;
                    }
                    .pagination-input {
                        width: 100%;
                        justify-content: center;
                    }
                    .modal-box {
                        padding: 0;
                        width: 98%;
                    }
                    .modal-header {
                        padding: 12px 16px 10px 16px;
                    }
                    .modal-header h3 {
                        font-size: 16px;
                    }
                    .modal-tabs-wrapper {
                        padding: 0 16px;
                    }
                    .modal-tabs {
                        padding: 8px 0;
                    }
                    .modal-tab {
                        padding: 6px 12px;
                        font-size: 12px;
                    }
                    .modal-body {
                        padding: 16px;
                    }
                    .detail-table .label {
                        min-width: 80px;
                        font-size: 12px;
                    }
                    .detail-table td {
                        padding: 6px 8px;
                        font-size: 12px;
                    }
                    .json-container {
                        max-height: calc(90vh - 280px);
                    }
                }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>
                            <i class="fas fa-database"></i> БДУ Explorer
                        </h1>
                        <div class="config-status">
                            <span class="dot green" id="statusDot"></span>
                            <span id="configStatusText">Подключено</span>
                            <i class="fas fa-database" style="margin-left: 6px; color: #64748b;"></i>
                            <span id="dbName" style="font-weight: 500;">—</span>
                        </div>
                    </div>

                    <div class="filter-panel">
                        <div class="field">
                            <i class="fas fa-search"></i>
                            <input type="text" id="searchInput" placeholder="Поиск по ID..." value="">
                        </div>
                        <div class="field">
                            <i class="fas fa-tag"></i>
                            <select id="severityFilter">
                                <option value="">Все уровни</option>
                                <option value="Критический">Критический</option>
                                <option value="Высокий">Высокий</option>
                                <option value="Средний">Средний</option>
                                <option value="Низкий">Низкий</option>
                            </select>
                        </div>
                    </div>

                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Название / Описание</th>
                                    <th>Уровень</th>
                                    <th>Дата публикации</th>
                                    <th>CVE ID</th>
                                    <th style="text-align:center; min-width:80px;">Действия</th>
                                </tr>
                            </thead>
                            <tbody id="bduTableBody">
                                <tr><td colspan="6" class="empty-state">
                                    <i class="fas fa-cloud-download-alt"></i>
                                    <div>Загрузка данных...</div>
                                </td></tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="pagination">
                        <button id="prevPageBtn" disabled><i class="fas fa-chevron-left"></i> Назад</button>
                        <span id="pageInfo">Страница 1 из 1</span>
                        <div class="pagination-input">
                            <span>Перейти к</span>
                            <input type="number" id="pageInput" min="1" value="1">
                            <button class="btn-go" id="goToPageBtn"><i class="fas fa-arrow-right"></i></button>
                        </div>
                        <button id="nextPageBtn">Вперед <i class="fas fa-chevron-right"></i></button>
                    </div>
                    <div class="footer-meta" id="totalCountInfo">Всего записей: —</div>
                </div>

                <!-- Модальное окно -->
                <div class="modal-overlay" id="detailModal">
                    <div class="modal-box">
                        <div class="modal-header">
                            <h3 id="modalTitle">Информация о БДУ</h3>
                            <button class="modal-close" id="modalClose">&times;</button>
                        </div>
                        <div class="modal-tabs-wrapper">
                            <div class="modal-tabs">
                                <button class="modal-tab active" data-tab="details">Детали</button>
                                <button class="modal-tab" data-tab="json">JSON</button>
                            </div>
                        </div>
                        <div class="modal-body">
                            <div class="modal-tab-content active" id="tab-details">
                                <div id="modalDetails"></div>
                            </div>
                            <div class="modal-tab-content" id="tab-json">
                                <div class="json-container">
                                    <div class="json-header">
                                        <span><i class="fas fa-code"></i> Исходный JSON</span>
                                        <button class="copy-btn" id="copyJsonBtn"><i class="fas fa-copy"></i> Копировать</button>
                                    </div>
                                    <pre id="jsonContent"></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <script>
                    const API_BASE = window.location.origin;

                    let currentPage = 1;
                    const pageSize = 20;
                    let totalRecords = 0;
                    let currentFilter = { search: '', severity: '' };

                    const tbody = document.getElementById('bduTableBody');
                    const searchInput = document.getElementById('searchInput');
                    const severityFilter = document.getElementById('severityFilter');
                    const prevBtn = document.getElementById('prevPageBtn');
                    const nextBtn = document.getElementById('nextPageBtn');
                    const pageInfo = document.getElementById('pageInfo');
                    const totalCountInfo = document.getElementById('totalCountInfo');
                    const dbNameSpan = document.getElementById('dbName');
                    const pageInput = document.getElementById('pageInput');
                    const goToPageBtn = document.getElementById('goToPageBtn');

                    const modalOverlay = document.getElementById('detailModal');
                    const modalTitle = document.getElementById('modalTitle');
                    const modalDetails = document.getElementById('modalDetails');
                    const modalClose = document.getElementById('modalClose');
                    const jsonContent = document.getElementById('jsonContent');
                    const copyJsonBtn = document.getElementById('copyJsonBtn');
                    const tabButtons = document.querySelectorAll('.modal-tab');

                    let currentBduData = null;
                    let currentBduId = null;
                    let currentViewMode = 'details';

                    // Поиск с задержкой
                    searchInput.addEventListener('input', function() {
                        const searchTerm = this.value.trim();
                        currentFilter.search = searchTerm;
                        currentPage = 1;
                        
                        clearTimeout(this._searchTimeout);
                        this._searchTimeout = setTimeout(() => {
                            refreshTable();
                        }, 300);
                    });

                    severityFilter.addEventListener('change', function() {
                        currentFilter.severity = this.value;
                        currentPage = 1;
                        refreshTable();
                    });

                    searchInput.addEventListener('keydown', function(e) {
                        if (e.key === 'Enter') {
                            clearTimeout(this._searchTimeout);
                            const searchTerm = this.value.trim();
                            currentFilter.search = searchTerm;
                            currentPage = 1;
                            refreshTable();
                        }
                    });

                    function getSeverityClass(severityText) {
                        if (!severityText) return 'severity-none';
                        const s = severityText.toLowerCase();
                        if (s.includes('критический')) return 'severity-critical';
                        if (s.includes('высокий')) return 'severity-high';
                        if (s.includes('средний')) return 'severity-medium';
                        if (s.includes('низкий')) return 'severity-low';
                        return 'severity-unknown';
                    }

                    function extractSeverityLevel(severityText) {
                        if (!severityText) return 'Неизвестно';
                        const s = severityText.toLowerCase();
                        if (s.includes('критический')) return 'Критический';
                        if (s.includes('высокий')) return 'Высокий';
                        if (s.includes('средний')) return 'Средний';
                        if (s.includes('низкий')) return 'Низкий';
                        return 'Неизвестно';
                    }

                    function formatDate(dateStr) {
                        if (!dateStr) return '—';
                        try {
                            const parts = dateStr.split('.');
                            if (parts.length === 3) {
                                const d = new Date(parts[2], parts[1]-1, parts[0]);
                                return d.toLocaleDateString('ru-RU', { year: 'numeric', month: 'short', day: 'numeric' });
                            }
                            return dateStr;
                        } catch { return dateStr; }
                    }

                    function formatDateFull(dateStr) {
                        if (!dateStr) return '—';
                        try {
                            const parts = dateStr.split('.');
                            if (parts.length === 3) {
                                const d = new Date(parts[2], parts[1]-1, parts[0]);
                                return d.toLocaleDateString('ru-RU', { year: 'numeric', month: 'long', day: 'numeric' });
                            }
                            return dateStr;
                        } catch { return dateStr; }
                    }

                    function renderReferencesShort(refs) {
                        if (!refs || refs.length === 0) {
                            return '<span style="color:#94a3b8;font-size:12px;">Нет ссылок</span>';
                        }
                        let html = '';
                        refs.slice(0, 2).forEach(ref => {
                            html += `<a href="${ref}" target="_blank" class="ref-link" title="${ref}"><i class="fas fa-external-link-alt"></i> ссылка</a>`;
                        });
                        if (refs.length > 2) {
                            html += `<span style="font-size:12px;color:#94a3b8;">+${refs.length - 2} ещё</span>`;
                        }
                        return html;
                    }

                    function renderReferencesFull(refs) {
                        if (!refs || refs.length === 0) return 'Нет ссылок';
                        let html = '';
                        refs.forEach(ref => {
                            html += `<a href="${ref}" target="_blank" class="ref-link"><i class="fas fa-external-link-alt"></i> ${ref}</a>`;
                        });
                        return html;
                    }

                    function escapeHtml(text) {
                        if (!text) return '—';
                        const div = document.createElement('div');
                        div.textContent = text;
                        return div.innerHTML;
                    }

                    function renderDetailTable(item) {
                        const bduId = item._id || '—';
                        const name = item.name || 'Нет названия';
                        const description = item.description || 'Нет описания';
                        const severity = item.severity || '—';
                        const severityLevel = extractSeverityLevel(severity);
                        const severityClass = getSeverityClass(severity);
                        const publication = formatDateFull(item.publication_date);
                        const identify = formatDateFull(item.identify_date);
                        const lastUpd = formatDateFull(item.last_upd_date);
                        const cvss = item.cvss || '—';
                        const cwes = item.cwes || [];
                        const cveIds = item.identifiers_CVE || [];
                        const sources = item.sources || [];
                        const vulnerableSoftware = item.vulnerable_software || [];
                        const solution = item.solution || '—';
                        const vulStatus = item.vul_status || '—';
                        const vulState = item.vul_state || '—';
                        const vulClass = item.vul_class || '—';
                        const vulElimination = item.vul_elimination || '—';
                        const exploitStatus = item.exploit_status || '—';
                        const fixStatus = item.fix_status || '—';
                        const environment = item.environment || [];
                        const other = item.other || '';

                        let cweHtml = 'Нет данных';
                        if (cwes.length > 0) {
                            cweHtml = cwes.map(c => `<span class="tag">${c}</span>`).join(' ');
                        }

                        let cveHtml = 'Нет данных';
                        if (cveIds.length > 0) {
                            cveHtml = cveIds.map(cve => 
                                `<a href="/api/cve/${cve}" target="_blank" class="cve-link">${cve}</a>`
                            ).join(' ');
                        }

                        let vulnSwHtml = 'Нет данных';
                        if (vulnerableSoftware.length > 0) {
                            vulnSwHtml = vulnerableSoftware.map(s => `<span class="tag">${s}</span>`).join(' ');
                        }

                        let envHtml = 'Нет данных';
                        if (environment.length > 0) {
                            envHtml = environment.map(e => `<span class="tag">${e}</span>`).join(' ');
                        }

                        return `
                            <table class="detail-table">
                                <tr><td class="label">ID</td><td class="value"><strong>${bduId}</strong></td></tr>
                                <tr><td class="label">Название</td><td class="value">${escapeHtml(name)}</td></tr>
                                <tr><td class="label">Описание</td><td class="value">${escapeHtml(description)}</td></tr>
                                <tr><td class="label">Уровень опасности</td><td class="value">
                                    <span class="severity-badge ${severityClass}">${severityLevel}</span>
                                    <div style="margin-top:4px;font-size:12px;color:#64748b;">${escapeHtml(severity)}</div>
                                </td></tr>
                                <tr><td class="label">CVSS вектор</td><td class="value"><code>${cvss}</code></td></tr>
                                <tr><td class="label">CWE</td><td class="value">${cweHtml}</td></tr>
                                <tr><td class="label">CVE ID</td><td class="value">${cveHtml}</td></tr>
                                <tr><td class="label">Статус уязвимости</td><td class="value">${vulStatus}</td></tr>
                                <tr><td class="label">Состояние</td><td class="value">${vulState}</td></tr>
                                <tr><td class="label">Класс уязвимости</td><td class="value">${vulClass}</td></tr>
                                <tr><td class="label">Устранение</td><td class="value">${vulElimination}</td></tr>
                                <tr><td class="label">Статус эксплуатации</td><td class="value">${exploitStatus}</td></tr>
                                <tr><td class="label">Статус исправления</td><td class="value">${fixStatus}</td></tr>
                                <tr><td class="label">Дата публикации</td><td class="value">${publication}</td></tr>
                                <tr><td class="label">Дата выявления</td><td class="value">${identify}</td></tr>
                                <tr><td class="label">Дата обновления</td><td class="value">${lastUpd}</td></tr>
                                <tr><td class="label">Уязвимое ПО</td><td class="value">${vulnSwHtml}</td></tr>
                                <tr><td class="label">Среда</td><td class="value">${envHtml}</td></tr>
                                <tr><td class="label">Решение</td><td class="value" style="white-space:pre-wrap;">${escapeHtml(solution)}</td></tr>
                                <tr><td class="label">Источники</td><td class="value">${renderReferencesFull(sources)}</td></tr>
                                ${other ? `<tr><td class="label">Прочее</td><td class="value">${escapeHtml(other)}</td></tr>` : ''}
                            </table>
                        `;
                    }

                    function updatePagination(totalPages) {
                        pageInfo.textContent = `Страница ${currentPage} из ${totalPages}`;
                        prevBtn.disabled = currentPage <= 1;
                        nextBtn.disabled = currentPage >= totalPages;
                        pageInput.value = currentPage;
                        pageInput.max = totalPages;
                    }

                    window.goToPage = function() {
                        let page = parseInt(pageInput.value);
                        const totalPages = Math.ceil(totalRecords / pageSize) || 1;
                        if (isNaN(page) || page < 1) page = 1;
                        if (page > totalPages) page = totalPages;
                        if (page !== currentPage) {
                            currentPage = page;
                            refreshTable();
                        } else {
                            pageInput.value = currentPage;
                        }
                    };

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

                    async function fetchBduItems(page = 1) {
                        const search = currentFilter.search.trim();
                        const severity = currentFilter.severity;
                        const params = new URLSearchParams({ page, limit: pageSize });
                        if (search) params.append('search', search);
                        if (severity) params.append('severity_text', severity);
                        try {
                            const resp = await fetch(`${API_BASE}/api/bdu/items?${params}`);
                            if (!resp.ok) throw new Error('Ошибка загрузки БДУ');
                            const data = await resp.json();
                            totalRecords = data.total || 0;
                            return data;
                        } catch (error) {
                            console.error('Ошибка загрузки БДУ:', error);
                            throw error;
                        }
                    }

                    function renderTable(data) {
                        if (!data || data.length === 0) {
                            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">
                                <i class="fas fa-inbox"></i>
                                <div>Записи не найдены</div>
                            </td></tr>`;
                            totalCountInfo.textContent = 'Всего записей: 0';
                            return;
                        }

                        let html = '';
                        data.forEach((item, index) => {
                            const bduId = item._id || '—';
                            const name = item.name || 'Без названия';
                            const description = item.description || '';
                            const severity = item.severity || '—';
                            const severityLevel = extractSeverityLevel(severity);
                            const severityClass = getSeverityClass(severity);
                            const publication = formatDate(item.publication_date);
                            const cveIds = item.identifiers_CVE || [];
                            const sources = item.sources || [];
                            const uniqueId = `desc-${index}-${bduId.replace(/[^a-zA-Z0-9]/g, '')}`;
                            const isLong = description.length > 120;
                            const displayText = name || description;

                            html += `<tr>
                                <td><span class="bdu-id">${bduId}</span></td>
                                <td class="desc-cell">
                                    <div class="desc-preview" id="${uniqueId}">${escapeHtml(displayText)}</div>
                                    ${isLong ? `<span class="desc-toggle" onclick="toggleDesc('${uniqueId}', this)">Показать полностью</span>` : ''}
                                </td>
                                <td>
                                    <span class="severity-badge ${severityClass}">${severityLevel}</span>
                                </td>
                                <td>${publication}</td>
                                <td class="references-cell">
                                    ${cveIds.length > 0 ? cveIds.map(c => `<span class="tag">${c}</span>`).join(' ') : '<span style="color:#94a3b8;">—</span>'}
                                </td>
                                <td class="actions-cell">
                                    <button class="action-btn expand-btn" onclick="showDetails('${bduId}')" title="Показать полную информацию">
                                        <i class="fas fa-ellipsis-h"></i>
                                    </button>
                                    <button class="action-btn json-btn" onclick="showJson('${bduId}')" title="Показать JSON">
                                        <i class="fas fa-code"></i>
                                    </button>
                                </td>
                            </tr>`;
                        });
                        tbody.innerHTML = html;
                        totalCountInfo.textContent = `Всего записей: ${totalRecords}`;
                        window._bduData = data;
                    }

                    window.toggleDesc = function(id, btn) {
                        const el = document.getElementById(id);
                        if (!el) return;
                        const isExpanded = el.classList.contains('expanded');
                        if (isExpanded) {
                            el.classList.remove('expanded');
                            btn.textContent = 'Показать полностью';
                        } else {
                            el.classList.add('expanded');
                            btn.textContent = 'Свернуть';
                        }
                    };

                    // ---------- МОДАЛЬНОЕ ОКНО ----------
                    window.showDetails = async function(bduId) {
                        try {
                            const resp = await fetch(`${API_BASE}/api/bdu/item/${bduId}`);
                            if (!resp.ok) throw new Error('Ошибка загрузки данных');
                            const result = await resp.json();
                            if (!result.status || !result.data) {
                                throw new Error('Данные не найдены');
                            }
                            
                            currentBduData = result.data;
                            currentBduId = bduId;
                            currentViewMode = 'details';
                            
                            modalTitle.textContent = `${bduId} — Полная информация`;
                            modalDetails.innerHTML = renderDetailTable(currentBduData);
                            
                            activateTab('details');
                            modalOverlay.classList.add('active');
                            document.body.style.overflow = 'hidden';
                        } catch (error) {
                            console.error('Ошибка загрузки данных:', error);
                            alert('Не удалось загрузить данные для этой записи');
                        }
                    };

                    window.showJson = async function(bduId) {
                        try {
                            const resp = await fetch(`${API_BASE}/api/bdu/item/${bduId}`);
                            if (!resp.ok) throw new Error('Ошибка загрузки JSON');
                            const result = await resp.json();
                            if (!result.status || !result.data) {
                                throw new Error('Данные не найдены');
                            }
                            
                            currentBduData = result.data;
                            currentBduId = bduId;
                            currentViewMode = 'json';
                            
                            modalTitle.textContent = `${bduId} — Исходный JSON`;
                            const formatted = JSON.stringify(currentBduData, null, 2);
                            jsonContent.textContent = formatted;
                            
                            activateTab('json');
                            modalOverlay.classList.add('active');
                            document.body.style.overflow = 'hidden';
                        } catch (error) {
                            console.error('Ошибка загрузки JSON:', error);
                            alert('Не удалось загрузить JSON для этой записи');
                        }
                    };

                    function activateTab(tabName) {
                        currentViewMode = tabName;
                        
                        tabButtons.forEach(btn => {
                            const tab = btn.dataset.tab;
                            btn.classList.toggle('active', tab === tabName);
                        });
                        
                        document.querySelectorAll('.modal-tab-content').forEach(el => {
                            const isActive = el.id === `tab-${tabName}`;
                            el.classList.toggle('active', isActive);
                        });
                        
                        if (tabName === 'json' && currentBduData) {
                            const formatted = JSON.stringify(currentBduData, null, 2);
                            jsonContent.textContent = formatted;
                        }
                        
                        if (tabName === 'details' && currentBduData) {
                            modalDetails.innerHTML = renderDetailTable(currentBduData);
                        }
                    }

                    tabButtons.forEach(btn => {
                        btn.addEventListener('click', function() {
                            const tab = this.dataset.tab;
                            activateTab(tab);
                        });
                    });

                    copyJsonBtn.addEventListener('click', function() {
                        const text = jsonContent.textContent;
                        if (!text) {
                            alert('Нет данных для копирования');
                            return;
                        }
                        navigator.clipboard.writeText(text).then(() => {
                            const originalText = this.innerHTML;
                            this.innerHTML = '<i class="fas fa-check"></i> Скопировано!';
                            setTimeout(() => {
                                this.innerHTML = originalText;
                            }, 2000);
                        }).catch(() => {
                            const textarea = document.createElement('textarea');
                            textarea.value = text;
                            document.body.appendChild(textarea);
                            textarea.select();
                            document.execCommand('copy');
                            document.body.removeChild(textarea);
                            const originalText = this.innerHTML;
                            this.innerHTML = '<i class="fas fa-check"></i> Скопировано!';
                            setTimeout(() => {
                                this.innerHTML = originalText;
                            }, 2000);
                        });
                    });

                    function closeModal() {
                        modalOverlay.classList.remove('active');
                        document.body.style.overflow = '';
                    }

                    modalClose.addEventListener('click', closeModal);

                    modalOverlay.addEventListener('click', (e) => {
                        if (e.target === modalOverlay) {
                            closeModal();
                        }
                    });

                    document.addEventListener('keydown', (e) => {
                        if (e.key === 'Escape') {
                            closeModal();
                        }
                    });

                    // ---------- ОБНОВЛЕНИЕ ТАБЛИЦЫ ----------
                    async function refreshTable() {
                        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">
                            <i class="fas fa-spinner fa-pulse"></i>
                            <div>Загрузка...</div>
                        </td></tr>`;
                        try {
                            const result = await fetchBduItems(currentPage);
                            renderTable(result.items);
                            const totalPages = Math.ceil(result.total / pageSize) || 1;
                            updatePagination(totalPages);
                        } catch (error) {
                            console.error('Ошибка загрузки:', error);
                            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">
                                <i class="fas fa-exclamation-triangle" style="color:#ef4444;"></i>
                                <div>Ошибка загрузки данных</div>
                            </td></tr>`;
                        }
                    }

                    // ---------- ПАГИНАЦИЯ ----------
                    prevBtn.addEventListener('click', () => {
                        if (currentPage > 1) { currentPage--; refreshTable(); }
                    });

                    nextBtn.addEventListener('click', () => {
                        currentPage++; refreshTable();
                    });

                    goToPageBtn.onclick = function(e) {
                        e.preventDefault();
                        window.goToPage();
                    };

                    pageInput.addEventListener('keydown', (e) => {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            window.goToPage();
                        }
                    });

                    pageInput.addEventListener('blur', () => {
                        const totalPages = Math.ceil(totalRecords / pageSize) || 1;
                        let val = parseInt(pageInput.value);
                        if (isNaN(val) || val < 1) val = currentPage;
                        if (val > totalPages) val = totalPages;
                        pageInput.value = val;
                    });

                    // ---------- ИНИЦИАЛИЗАЦИЯ ----------
                    async function init() {
                        await fetchConfig();
                        await refreshTable();
                    }

                    init();
                </script>
            </body>
        </html>
    """

@app.get("/api/bdu/items")
async def get_bdu_items(
    page: int = Query(1, ge=1, description="Номер страницы"),
    limit: int = Query(20, ge=1, le=100, description="Количество записей на странице"),
    search: Optional[str] = Query(None, description="Поиск по ID"),
    severity_text: Optional[str] = Query(None, description="Фильтр по уровню опасности (подстрока)")
):
    """
    Получить список записей БДУ из MongoDB с пагинацией и фильтрацией
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

        collection = base["BDU"]
        
        # Строим фильтр
        filter_condition = {}
        if search and search.strip():
            filter_condition["_id"] = {"$regex": search.strip(), "$options": "i"}
        if severity_text and severity_text.strip():
            # Ищем подстроку в поле severity (регистронезависимо)
            filter_condition["severity"] = {"$regex": severity_text.strip(), "$options": "i"}
        
        # Общее количество
        total = await collection.count_documents(filter_condition)
        
        # Пагинация
        skip = (page - 1) * limit
        cursor = collection.find(filter_condition).sort("_id", 1).skip(skip).limit(limit)
        items = await cursor.to_list(length=limit)
        
        # Преобразуем _id (он уже строка, но для единообразия)
        for item in items:
            if "_id" in item:
                # _id уже строка, но если это ObjectId, преобразуем
                if not isinstance(item["_id"], str):
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
        print(f"❌ Ошибка получения БДУ: {e}")
        import traceback
        traceback.print_exc()
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

@app.get("/api/bdu/item/{bdu_id}")
async def get_bdu_item(bdu_id: str):
    """Получить конкретную запись БДУ по ID"""
    try:
        if base is None:
            return JSONResponse(
                status_code=503,
                content={"status": False, "message": "MongoDB не доступна"}
            )
        
        collection = base["BDU"]
        doc = await collection.find_one({"_id": bdu_id})
        
        if not doc:
            return JSONResponse(
                status_code=404,
                content={"status": False, "message": f"Запись {bdu_id} не найдена"}
            )
        
        if "_id" in doc and not isinstance(doc["_id"], str):
            doc["_id"] = str(doc["_id"])
        
        return {
            "status": True,
            "data": doc
        }
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": False, "message": str(e)}
        )

# ---------- Остальные эндпоинты (конфиг, статус) остаются без изменений ----------
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

@app.get("/api/db-status")
async def get_db_status():
    """Проверить статус подключения к MongoDB"""
    if base is None:
        return {
            "status": False,
            "message": "MongoDB не подключена"
        }
    
    try:
        # Проверяем наличие коллекции BDU
        collections = await base.list_collection_names()
        has_bdu = "BDU" in collections
        bdu_count = 0
        if has_bdu:
            collection = base["BDU"]
            bdu_count = await collection.count_documents({})
        
        return {
            "status": True,
            "message": "MongoDB подключена",
            "database": name_base,
            "collections": collections,
            "bdu_count": bdu_count
        }
    except Exception as e:
        return {
            "status": False,
            "message": f"Ошибка: {str(e)}"
        }

if __name__ == "__main__":
    base, name_base = asyncio.run(init_mongo())
    uvicorn.run("bdu_main:app", host="0.0.0.0", port=8004, reload=True)