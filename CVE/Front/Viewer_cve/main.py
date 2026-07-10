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
    .cve-id {
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

    /* Модальное окно */
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
        padding: 30px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        overflow-y: auto;
        position: relative;
        animation: modalFadeIn 0.2s ease;
    }
    @keyframes modalFadeIn {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
    }
    .modal-box h3 {
        margin-bottom: 16px;
        color: #1e293b;
        font-size: 20px;
        display: flex;
        align-items: center;
        gap: 12px;
        padding-right: 40px;
    }
    .modal-box .modal-close {
        position: absolute;
        top: 12px;
        right: 16px;
        font-size: 28px;
        cursor: pointer;
        color: #94a3b8;
        background: none;
        border: none;
        transition: 0.15s;
        line-height: 1;
    }
    .modal-box .modal-close:hover {
        color: #1e293b;
        transform: scale(1.1);
    }

    .modal-tabs {
        display: flex;
        gap: 8px;
        margin-bottom: 16px;
        border-bottom: 2px solid #e9edf2;
        padding-bottom: 12px;
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
    .modal-tab-content {
        display: none;
    }
    .modal-tab-content.active {
        display: block;
    }

    /* Таблица в модальном окне */
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

    /* JSON стили */
    .json-container {
        background: #1e1e1e;
        border-radius: 12px;
        padding: 0;
        overflow: hidden;
        margin-top: 8px;
        max-height: calc(90vh - 250px);
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
        .filter-panel .actions { margin-left: 0; width: 100%; }
        .filter-panel .actions .btn { flex: 1; justify-content: center; }
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
            padding: 16px;
            width: 98%;
        }
        .detail-table .label {
            min-width: 80px;
            font-size: 12px;
        }
        .detail-table td {
            padding: 6px 8px;
            font-size: 12px;
        }
        .modal-tabs {
            gap: 4px;
        }
        .modal-tab {
            padding: 6px 12px;
            font-size: 12px;
        }
    }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>
            <i class="fas fa-shield-alt"></i> CVE Explorer
            <span class="badge">v2</span>
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
            <input type="text" id="searchInput" placeholder="CVE ID" value="">
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

    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>CVE ID</th>
                    <th>Описание</th>
                    <th>Уровень</th>
                    <th>Дата публикации</th>
                    <th>Ссылки</th>
                    <th style="text-align:center; min-width:80px;">Действия</th>
                </tr>
            </thead>
            <tbody id="cveTableBody">
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
        <button class="modal-close" id="modalClose">&times;</button>
        <h3 id="modalTitle">Информация о CVE</h3>
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

<script>
    const API_BASE = window.location.origin;

    let currentPage = 1;
    const pageSize = 20;
    let totalRecords = 0;
    let currentFilter = { search: '', severity: '' };
    let currentCveData = null;
    let currentCveId = '';

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
    const pageInput = document.getElementById('pageInput');
    const goToPageBtn = document.getElementById('goToPageBtn');

    const modalOverlay = document.getElementById('detailModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalDetails = document.getElementById('modalDetails');
    const modalClose = document.getElementById('modalClose');
    const jsonContent = document.getElementById('jsonContent');
    const copyJsonBtn = document.getElementById('copyJsonBtn');
    const tabButtons = document.querySelectorAll('.modal-tab');

    function getSeverityClass(severity) {
        if (!severity) return 'severity-none';
        const s = severity.toUpperCase();
        if (s.includes('CRITICAL')) return 'severity-critical';
        if (s.includes('HIGH')) return 'severity-high';
        if (s.includes('MEDIUM')) return 'severity-medium';
        if (s.includes('LOW')) return 'severity-low';
        return 'severity-unknown';
    }

    function formatDate(dateStr) {
        if (!dateStr) return '—';
        try {
            const d = new Date(dateStr);
            return d.toLocaleDateString('ru-RU', { year: 'numeric', month: 'short', day: 'numeric' });
        } catch { return dateStr; }
    }

    function formatDateFull(dateStr) {
        if (!dateStr) return '—';
        try {
            const d = new Date(dateStr);
            return d.toLocaleString('ru-RU', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch { return dateStr; }
    }

    function getReferences(item) {
        return item.containers?.cna?.references || [];
    }

    function getFullDescription(item) {
        return item.containers?.cna?.descriptions?.[0]?.value || 'Нет описания';
    }

    function renderReferencesShort(refs) {
        if (!refs || refs.length === 0) {
            return '<span style="color:#94a3b8;font-size:12px;">Нет ссылок</span>';
        }
        let html = '';
        refs.slice(0, 2).forEach(ref => {
            const url = ref.url || '#';
            const name = ref.name || 'Ссылка';
            html += `<a href="${url}" target="_blank" class="ref-link" title="${name}"><i class="fas fa-external-link-alt"></i> ${name}</a>`;
        });
        if (refs.length > 2) {
            html += `<span style="font-size:12px;color:#94a3b8;">+${refs.length - 2} ещё</span>`;
        }
        return html;
    }

    function renderReferencesFull(refs) {
        if (!refs || refs.length === 0) {
            return 'Нет ссылок';
        }
        let html = '';
        refs.forEach(ref => {
            const url = ref.url || '#';
            const name = ref.name || 'Ссылка';
            html += `<a href="${url}" target="_blank" class="ref-link"><i class="fas fa-external-link-alt"></i> ${name}</a>`;
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
        const cveId = item.cveMetadata?.cveId || '—';
        const desc = getFullDescription(item);
        const severity = item.severity_info?.severity || 'NONE';
        const score = item.severity_info?.score || 0;
        const severityClass = getSeverityClass(severity);
        const published = formatDateFull(item.cveMetadata?.datePublished);
        const updated = formatDateFull(item.cveMetadata?.dateUpdated);
        const reserved = formatDateFull(item.cveMetadata?.dateReserved);
        const state = item.cveMetadata?.state || '—';
        const assigner = item.cveMetadata?.assignerShortName || '—';
        const refs = getReferences(item);
        
        // Получаем affected продукты
        const affected = item.containers?.cna?.affected || [];
        let affectedHtml = 'Нет данных';
        if (affected.length > 0) {
            affectedHtml = affected.map(a => {
                const vendor = a.vendor || '—';
                const product = a.product || '—';
                const versions = a.versions || [];
                const versionStr = versions.map(v => v.version || '—').join(', ');
                const status = a.defaultStatus || '—';
                return `<div><span class="tag">${vendor}</span> → <strong>${product}</strong> (${versionStr}) <span style="color:#64748b;font-size:11px;">[${status}]</span></div>`;
            }).join('');
        }

        // Получаем problem types
        const problemTypes = item.containers?.cna?.problemTypes || [];
        let problemHtml = 'Нет данных';
        if (problemTypes.length > 0 && problemTypes[0].descriptions) {
            problemHtml = problemTypes[0].descriptions.map(d => {
                const cwe = d.cweId || '—';
                const desc2 = d.description || '—';
                return `<div><span class="tag">${cwe}</span> ${desc2}</div>`;
            }).join('');
        }

        // CVSS метрики
        const metrics = item.containers?.cna?.metrics || [];
        let metricsHtml = 'Нет данных';
        if (metrics.length > 0) {
            metricsHtml = metrics.map(m => {
                let parts = [];
                for (const [key, val] of Object.entries(m)) {
                    if (key !== 'format' && key !== 'scenarios' && typeof val === 'object' && val !== null) {
                        const version = val.version || '—';
                        const vector = val.vectorString || '—';
                        const baseScore = val.baseScore || '—';
                        const baseSeverity = val.baseSeverity || '—';
                        parts.push(`<div><strong>${key}</strong> (v${version}) | Score: ${baseScore} | Severity: ${baseSeverity}</div>`);
                        if (vector !== '—') {
                            parts.push(`<div style="font-size:11px;color:#64748b;padding-left:12px;">Vector: ${vector}</div>`);
                        }
                    }
                }
                return parts.join('');
            }).join('');
        }

        // ADP метрики
        const adp = item.containers?.adp || [];
        let adpHtml = 'Нет данных';
        if (adp.length > 0) {
            adpHtml = adp.map(a => {
                const provider = a.providerMetadata?.shortName || '—';
                const metrics2 = a.metrics || [];
                let metricsHtml2 = metrics2.map(m => {
                    if (m.other) {
                        const content = m.other.content || {};
                        return `<div><strong>SSVC</strong> | Exploitation: ${content.Exploitation || '—'} | Automatable: ${content.Automatable || '—'}</div>`;
                    }
                    return '';
                }).join('');
                return `<div><span class="tag">${provider}</span> ${metricsHtml2}</div>`;
            }).join('');
        }

        return `
            <table class="detail-table">
                <tr><td class="label">CVE ID</td><td class="value"><strong>${cveId}</strong></td></tr>
                <tr><td class="label">Описание</td><td class="value">${escapeHtml(desc)}</td></tr>
                <tr><td class="label">Уровень</td><td class="value"><span class="severity-badge ${severityClass}">${severity}</span> ${score ? `(Score: ${score})` : ''}</td></tr>
                <tr><td class="label">Состояние</td><td class="value"><span class="tag">${state}</span></td></tr>
                <tr><td class="label">Назначил</td><td class="value">${assigner}</td></tr>
                <tr><td class="label">Дата публикации</td><td class="value">${published}</td></tr>
                <tr><td class="label">Дата резервирования</td><td class="value">${reserved}</td></tr>
                <tr><td class="label">Дата обновления</td><td class="value">${updated}</td></tr>
                <tr><td class="label">Затронутые продукты</td><td class="value">${affectedHtml}</td></tr>
                <tr><td class="label">Типы проблем</td><td class="value">${problemHtml}</td></tr>
                <tr><td class="label">CVSS метрики</td><td class="value">${metricsHtml}</td></tr>
                <tr><td class="label">ADP метрики</td><td class="value">${adpHtml}</td></tr>
                <tr><td class="label">Ссылки</td><td class="value">${renderReferencesFull(refs)}</td></tr>
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

    async function fetchCVE(page = 1) {
        const search = currentFilter.search.trim();
        const severity = currentFilter.severity;
        const params = new URLSearchParams({ page, limit: pageSize });
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

    function renderTable(data) {
        if (!data || data.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">
                <i class="fas fa-inbox"></i>
                <div>Уязвимости не найдены</div>
            </td></tr>`;
            totalCountInfo.textContent = 'Всего записей: 0';
            return;
        }

        let html = '';
        data.forEach((item, index) => {
            const cveId = item.cveMetadata?.cveId || item._id || '—';
            const desc = getFullDescription(item);
            const severity = item.severity_info?.severity || 'NONE';
            const score = item.severity_info?.score || 0;
            const severityClass = getSeverityClass(severity);
            const published = formatDate(item.cveMetadata?.datePublished);
            const refs = getReferences(item);
            const uniqueId = `desc-${index}-${cveId.replace(/[^a-zA-Z0-9]/g, '')}`;
            const isLong = desc.length > 120;

            html += `<tr>
                <td><span class="cve-id">${cveId}</span></td>
                <td class="desc-cell">
                    <div class="desc-preview" id="${uniqueId}">${escapeHtml(desc)}</div>
                    ${isLong ? `<span class="desc-toggle" onclick="toggleDesc('${uniqueId}', this)">Показать полностью</span>` : ''}
                </td>
                <td>
                    <span class="severity-badge ${severityClass}">${severity}</span>
                    ${score ? `<span style="font-size:11px;color:#64748b;display:block;">Score: ${score}</span>` : ''}
                </td>
                <td>${published}</td>
                <td class="references-cell">${renderReferencesShort(refs)}</td>
                <td class="actions-cell">
                    <button class="action-btn expand-btn" onclick="showDetails('${cveId.replace(/'/g, "\\'")}')" title="Показать полную информацию">
                        <i class="fas fa-ellipsis-h"></i>
                    </button>
                    <button class="action-btn json-btn" onclick="showJson('${cveId.replace(/'/g, "\\'")}')" title="Показать JSON">
                        <i class="fas fa-code"></i>
                    </button>
                </td>
            </tr>`;
        });
        tbody.innerHTML = html;
        totalCountInfo.textContent = `Всего записей: ${totalRecords}`;
        window._cveData = data;
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

    window.showDetails = async function(cveId) {
        try {
            const resp = await fetch(`${API_BASE}/api/cve/${cveId}`);
            if (!resp.ok) throw new Error('Ошибка загрузки данных');
            const result = await resp.json();
            if (!result.status || !result.data) {
                throw new Error('Данные не найдены');
            }
            const item = result.data;
            currentCveData = item;
            currentCveId = cveId;
            
            modalTitle.textContent = `${cveId} — Полная информация`;
            modalDetails.innerHTML = renderDetailTable(item);
            
            activateTab('details');
            modalOverlay.classList.add('active');
            document.body.style.overflow = 'hidden';
        } catch (error) {
            console.error('Ошибка загрузки данных:', error);
            alert('Не удалось загрузить данные для этой CVE');
        }
    };

    window.showJson = async function(cveId) {
        try {
            const resp = await fetch(`${API_BASE}/api/cve/${cveId}`);
            if (!resp.ok) throw new Error('Ошибка загрузки JSON');
            const result = await resp.json();
            if (!result.status || !result.data) {
                throw new Error('Данные не найдены');
            }
            const jsonData = result.data;
            currentCveData = jsonData;
            currentCveId = cveId;
            
            modalTitle.textContent = `${cveId} — Исходный JSON`;
            const formatted = JSON.stringify(jsonData, null, 2);
            jsonContent.textContent = formatted;
            
            activateTab('json');
            modalOverlay.classList.add('active');
            document.body.style.overflow = 'hidden';
        } catch (error) {
            console.error('Ошибка загрузки JSON:', error);
            alert('Не удалось загрузить JSON для этой CVE');
        }
    };

    function activateTab(tabName) {
        tabButtons.forEach(btn => {
            const tab = btn.dataset.tab;
            btn.classList.toggle('active', tab === tabName);
        });
        document.querySelectorAll('.modal-tab-content').forEach(el => {
            el.classList.toggle('active', el.id === `tab-${tabName}`);
        });
    }

    tabButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const tab = this.dataset.tab;
            activateTab(tab);
            // Если переключаемся на JSON, а данных нет - загружаем
            if (tab === 'json' && !jsonContent.textContent && currentCveId) {
                showJson(currentCveId);
            }
        });
    });

    copyJsonBtn.addEventListener('click', function() {
        const text = jsonContent.textContent;
        if (!text) return;
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

    modalClose.addEventListener('click', () => {
        modalOverlay.classList.remove('active');
        document.body.style.overflow = '';
    });

    modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) {
            modalOverlay.classList.remove('active');
            document.body.style.overflow = '';
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            modalOverlay.classList.remove('active');
            document.body.style.overflow = '';
        }
    });

    async function refreshTable() {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">
            <i class="fas fa-spinner fa-pulse"></i>
            <div>Загрузка...</div>
        </td></tr>`;
        try {
            const result = await fetchCVE(currentPage);
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
    search: Optional[str] = Query(None, description="Поиск по ID"),
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
                        {"cveMetadata.cveId": {"$regex": search_term, "$options": "i"}}
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
        pipeline.append({
            "$addFields": {
                "references": "$containers.cna.references"
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
                                {"case": {"$eq": ["$max_cvss_score", None]}, "then": "NONE"},
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