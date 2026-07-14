from fastapi import APIRouter, File, UploadFile, Form, HTTPException, BackgroundTasks
import redis.asyncio as redis
from src.help_func import clone_cve_in_mongo, clone_bdu_xml_in_mongo
from pydantic import BaseModel, HttpUrl
from fastapi.responses import HTMLResponse
import os
import tempfile
import shutil
import uuid
import asyncio
from datetime import datetime
import json
from pymongo import MongoClient
import zipfile
import xml.etree.ElementTree as ET

router = APIRouter()

redis_client = redis.Redis(
    host='my-redis',
    port=6379,
    decode_responses=True,
    socket_connect_timeout=5
)

# Подключение к MongoDB
mongo_client = MongoClient('mongodb://my-mongo:27017/')
db = mongo_client['cve_db']
bdu_collection = db['bdu']

# Хранилище для статусов задач
task_statuses = {}

class Repo_Schema(BaseModel):

    update_url_cve: HttpUrl
    update_url_bdu: HttpUrl
    name_base: str

async def get_config_from_redis():
    """Получить конфигурацию из Redis"""
    try:
        config = await redis_client.hgetall("my_config")
        if not config:
            return {
                "update_url_cve": "",
                "update_url_bdu": "",
                "name_base": "",
            }
        return config
    except Exception as e:
        print(f"Redis error: {e}")
        return {
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
                <title>CVE/BDU Загрузка в базу данных</title>
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

                    .btn-post {
                        background: #4CAF50;
                    }

                    .btn-post:hover {
                        background: #388E3C;
                        transform: scale(1.02);
                    }

                    .btn-get {
                        background: #2196F3;
                    }

                    .btn-get:hover {
                        background: #1976D2;
                        transform: scale(1.02);
                    }

                    .btn:disabled {
                        opacity: 0.6;
                        cursor: not-allowed;
                        transform: none;
                    }

                    .btn-small {
                        padding: 8px 16px;
                        border: none;
                        border-radius: 6px;
                        font-size: 0.85em;
                        font-weight: 600;
                        cursor: pointer;
                        transition: all 0.3s ease;
                        color: white;
                        background: #667eea;
                    }

                    .btn-small:hover {
                        background: #5a67d8;
                        transform: translateY(-2px);
                    }

                    .btn-small.danger {
                        background: #e74c3c;
                    }

                    .btn-small.danger:hover {
                        background: #c0392b;
                    }

                    .btn-small.success {
                        background: #4CAF50;
                    }

                    .btn-small.success:hover {
                        background: #388E3C;
                    }

                    .file-selector {
                        background: #f8f9fa;
                        border: 2px dashed #667eea;
                        border-radius: 12px;
                        padding: 30px 20px;
                        margin: 15px 0;
                        text-align: center;
                        transition: all 0.3s ease;
                        cursor: pointer;
                    }

                    .file-selector:hover {
                        background: #e8ecf9;
                        border-color: #5a67d8;
                        transform: scale(1.02);
                    }

                    .file-selector.dragover {
                        background: #d4d9f5;
                        border-color: #4c51bf;
                        transform: scale(1.05);
                    }

                    .file-selector .icon {
                        font-size: 3em;
                        display: block;
                        margin-bottom: 10px;
                    }

                    .file-selector .text {
                        font-size: 1em;
                        color: #555;
                    }

                    .file-selector .subtext {
                        font-size: 0.85em;
                        color: #888;
                        margin-top: 5px;
                    }

                    .file-selector input[type="file"] {
                        display: none;
                    }

                    .file-list {
                        margin: 15px 0;
                        max-height: 200px;
                        overflow-y: auto;
                        border: 1px solid #e0e0e0;
                        border-radius: 8px;
                        padding: 10px;
                        background: #fafafa;
                    }

                    .file-list .file-item {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 6px 10px;
                        margin: 2px 0;
                        border-radius: 5px;
                        background: white;
                        transition: background 0.2s ease;
                    }

                    .file-list .file-item:hover {
                        background: #f0f0f0;
                    }

                    .file-list .file-name {
                        font-family: 'Courier New', monospace;
                        font-size: 0.9em;
                        color: #333;
                        display: flex;
                        align-items: center;
                        gap: 8px;
                        flex: 1;
                    }

                    .file-list .file-name .file-icon {
                        font-size: 1.2em;
                    }

                    .file-list .file-size {
                        font-size: 0.8em;
                        color: #888;
                        padding-left: 10px;
                    }

                    .file-list .file-type {
                        font-size: 0.75em;
                        padding: 2px 8px;
                        border-radius: 12px;
                        background: #667eea;
                        color: white;
                        font-weight: 600;
                        text-transform: uppercase;
                        white-space: nowrap;
                    }

                    .file-list .file-type.cve {
                        background: #4CAF50;
                    }

                    .file-list .file-type.bdu {
                        background: #FF9800;
                    }

                    .file-list .file-type.other {
                        background: #9E9E9E;
                    }

                    .file-list .remove-file {
                        color: #e74c3c;
                        cursor: pointer;
                        padding: 0 8px;
                        font-weight: bold;
                        font-size: 1.2em;
                        transition: transform 0.2s ease;
                    }

                    .file-list .remove-file:hover {
                        transform: scale(1.3);
                    }

                    .file-list-empty {
                        text-align: center;
                        color: #999;
                        padding: 15px;
                        font-style: italic;
                    }

                    .selected-files-count {
                        display: inline-block;
                        background: #667eea;
                        color: white;
                        padding: 2px 12px;
                        border-radius: 12px;
                        font-size: 0.8em;
                        font-weight: bold;
                        margin-left: 10px;
                    }

                    .file-info {
                        background: #e3f2fd;
                        padding: 15px;
                        border-radius: 8px;
                        margin: 10px 0;
                        border-left: 4px solid #2196F3;
                    }

                    .file-info .file-item {
                        padding: 5px 0;
                        font-size: 0.9em;
                    }

                    .file-info .file-label {
                        font-weight: bold;
                        color: #1976D2;
                    }

                    .checkbox-group {
                        display: flex;
                        gap: 20px;
                        margin: 10px 0;
                        padding: 10px;
                        background: #f5f5f5;
                        border-radius: 8px;
                    }

                    .checkbox-group label {
                        display: flex;
                        align-items: center;
                        gap: 8px;
                        cursor: pointer;
                        font-weight: 500;
                        color: #333;
                    }

                    .checkbox-group input[type="checkbox"] {
                        width: 18px;
                        height: 18px;
                        cursor: pointer;
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

                    .progress-wrapper {
                        background: white;
                        border-radius: 15px;
                        padding: 20px 30px;
                        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
                        margin-top: 10px;
                    }

                    .progress-top {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        margin-bottom: 8px;
                        flex-wrap: wrap;
                    }

                    .progress-label {
                        font-weight: 600;
                        color: #333;
                    }

                    .progress-percent {
                        font-weight: 700;
                        color: #667eea;
                        font-size: 1.1em;
                    }

                    .progress-track {
                        width: 100%;
                        height: 14px;
                        background: #e9ecef;
                        border-radius: 30px;
                        overflow: hidden;
                        position: relative;
                        box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
                    }

                    .progress-fill {
                        height: 100%;
                        width: 0%;
                        background: linear-gradient(90deg, #667eea, #764ba2);
                        border-radius: 30px;
                        transition: width 0.25s ease;
                        position: relative;
                    }

                    .progress-fill.indeterminate {
                        width: 40%;
                        animation: shimmer 1.2s infinite ease-in-out;
                        background: linear-gradient(90deg, #667eea, #764ba2, #667eea);
                        background-size: 200% 100%;
                    }

                    @keyframes shimmer {
                        0% { background-position: 200% 0; }
                        100% { background-position: -200% 0; }
                    }

                    .progress-message {
                        margin-top: 10px;
                        font-size: 0.95em;
                        color: #555;
                        min-height: 1.6em;
                    }

                    .progress-message.error {
                        color: #d32f2f;
                        font-weight: 500;
                    }

                    .progress-message.success {
                        color: #2e7d32;
                        font-weight: 500;
                    }

                    .button-group {
                        display: flex;
                        gap: 10px;
                        margin: 10px 0;
                        flex-wrap: wrap;
                    }

                    .button-group .btn-small {
                        flex: 1;
                        min-width: 100px;
                    }

                    .task-id-display {
                        background: #f0f0f0;
                        padding: 8px 12px;
                        border-radius: 6px;
                        font-family: monospace;
                        font-size: 0.85em;
                        color: #555;
                        margin: 10px 0;
                        display: none;
                    }

                    .task-id-display.show {
                        display: block;
                    }

                    .restore-notice {
                        background: #fff3cd;
                        border: 1px solid #ffc107;
                        border-radius: 8px;
                        padding: 12px 15px;
                        margin: 10px 0;
                        display: none;
                        color: #856404;
                    }

                    .restore-notice.show {
                        display: block;
                    }

                    .reload-btn {
                        background: #667eea;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        padding: 6px 15px;
                        cursor: pointer;
                        font-size: 0.9em;
                        transition: background 0.3s ease;
                    }

                    .reload-btn:hover {
                        background: #5a67d8;
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

                        .progress-wrapper {
                            padding: 15px 20px;
                        }

                        .button-group .btn-small {
                            min-width: 80px;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>CVE/BDU Загрузить файлы</h1>
                        <p>Выберите файлы CVE и/или BDU (XML или ZIP) для загрузки в MongoDB</p>
                        <div style="margin-top: 10px;">
                            <button class="reload-btn" onclick="clearAndRefresh()" style="background: #e74c3c; margin-left: 10px;">🗑️ Очистить и обновить</button>
                        </div>
                    </div>

                    <div class="grid">
                        <div class="card">
                            <div class="card-header">
                                <h2>Загрузить файлы</h2>
                            </div>
                            <div class="card-body">
                                <div class="restore-notice" id="restoreNotice">
                                    Обнаружена выполняющаяся задача. Статус обновляется...
                                </div>
                                
                                <p>Выберите файлы для загрузки</p>
                                
                                <div class="file-selector" id="fileSelector" onclick="selectFiles()">
                                    <span class="icon">📄</span>
                                    <div class="text">Нажмите для выбора файлов</div>
                                    <div class="subtext">или перетащите файлы сюда</div>
                                    <input type="file" id="fileInput" multiple accept=".xml,.zip,.json,.csv,.txt">
                                </div>
                                
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 15px;">
                                    <span style="font-weight: 600; color: #333;">Выбранные файлы:</span>
                                    <span class="selected-files-count" id="filesCount">0</span>
                                </div>
                                <div class="file-list" id="fileList">
                                    <div class="file-list-empty">Файлы не выбраны</div>
                                </div>
                                
                                <div class="button-group">
                                    <button class="btn-small danger" onclick="clearAllFiles()">Очистить</button>
                                </div>
                                
                                <div class="checkbox-group">
                                    <label>
                                        <input type="checkbox" id="loadCve" checked>
                                        Загрузить CVE
                                    </label>
                                    <label>
                                        <input type="checkbox" id="loadBdu" checked>
                                        Загрузить BDU
                                    </label>
                                </div>
                                
                                <div class="file-info">
                                    <div class="file-item"><span class="file-label">Файл CVE:</span> <span id="cveFileName">Не выбран</span></div>
                                    <div class="file-item"><span class="file-label">Файл BDU:</span> <span id="bduFileName">Не выбран</span></div>
                                </div>
                                
                                <button class="btn btn-post" id="uploadBtn" onclick="uploadFiles()">
                                    Загрузить в базу
                                </button>
                                
                                <div class="task-id-display" id="taskIdDisplay">
                                    ID задачи: <span id="taskIdValue"></span>
                                </div>
                                
                                <div id="result1" class="result-container"><pre></pre></div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <h2>Конфигурация</h2>
                            </div>
                            <div class="card-body">
                                <p>Просмотр текущей конфигурации из Redis</p>
                                <button class="btn btn-get" onclick="callAPI('GET', '/config', 'result2')">
                                    Показать конфигурацию
                                </button>
                                <div id="result2" class="result-container"><pre></pre></div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="progress-wrapper" id="progressWrapper">
                        <div class="progress-top">
                            <span class="progress-label" id="progressLabel">Ожидание</span>
                            <span class="progress-percent" id="progressPercent">0%</span>
                        </div>
                        <div class="progress-track">
                            <div class="progress-fill" id="progressFill" style="width:0%;"></div>
                        </div>
                        <div class="progress-message" id="progressMessage">Готов к работе</div>
                    </div>
                </div>

                <script>
                    let selectedFiles = [];
                    let cveFile = null;
                    let bduFile = null;
                    let currentTaskId = null;
                    let statusCheckInterval = null;
                    let isRestored = false;

                    const progressFill = document.getElementById('progressFill');
                    const progressPercent = document.getElementById('progressPercent');
                    const progressLabel = document.getElementById('progressLabel');
                    const progressMessage = document.getElementById('progressMessage');

                    function refreshPage() {
                        window.location.href = window.location.pathname;
                    }

                    function clearAndRefresh() {
                        localStorage.removeItem('activeTaskId');
                        if (statusCheckInterval) {
                            clearInterval(statusCheckInterval);
                            statusCheckInterval = null;
                        }
                        window.location.href = window.location.pathname;
                    }

                    function saveTaskId(taskId) {
                        if (taskId) {
                            localStorage.setItem('activeTaskId', taskId);
                        } else {
                            localStorage.removeItem('activeTaskId');
                        }
                    }

                    function getSavedTaskId() {
                        return localStorage.getItem('activeTaskId');
                    }

                    function clearSavedTaskId() {
                        localStorage.removeItem('activeTaskId');
                    }

                    function setProgress(percent, label, message, isError = false, isSuccess = false) {
                        const clamped = Math.min(100, Math.max(0, percent));
                        progressFill.style.width = clamped + '%';
                        progressFill.classList.remove('indeterminate');
                        progressPercent.textContent = clamped + '%';
                        if (label) progressLabel.textContent = label;
                        if (message !== undefined) {
                            progressMessage.textContent = message;
                            progressMessage.className = 'progress-message';
                            if (isError) progressMessage.classList.add('error');
                            if (isSuccess) progressMessage.classList.add('success');
                        }
                    }

                    function setIndeterminate(label, message) {
                        progressFill.classList.add('indeterminate');
                        progressFill.style.width = '40%';
                        progressPercent.textContent = '…';
                        if (label) progressLabel.textContent = label;
                        if (message !== undefined) {
                            progressMessage.textContent = message;
                            progressMessage.className = 'progress-message';
                        }
                    }

                    function selectFiles() {
                        document.getElementById('fileInput').click();
                    }

                    document.getElementById('fileInput').addEventListener('change', function(e) {
                        if (this.files && this.files.length > 0) {
                            const filesArray = Array.from(this.files);
                            filesArray.forEach(file => {
                                if (!selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
                                    selectedFiles.push(file);
                                }
                            });
                            updateFileList();
                            this.value = '';
                        }
                    });

                    function detectFileType(filename) {
                        const lower = filename.toLowerCase();
                        
                        // Проверяем на CVE
                        const cvePatterns = ['cve', 'vulnerability', 'nvd', 'vuln'];
                        for (const pattern of cvePatterns) {
                            if (lower.includes(pattern)) return 'cve';
                        }
                        
                        // Проверяем на BDU
                        const bduPatterns = ['bdu', 'bd', 'vul'];
                        for (const pattern of bduPatterns) {
                            if (lower.includes(pattern)) return 'bdu';
                        }
                        
                        return 'other';
                    }

                    function getFileIcon(filename) {
                        const ext = filename.split('.').pop().toLowerCase();
                        const icons = {
                            'xml': '📄',
                            'json': '📋',
                            'csv': '📊',
                            'txt': '📝',
                            'zip': '📦',
                            'gz': '📦',
                            'tar': '📦'
                        };
                        return icons[ext] || '📄';
                    }

                    function formatFileSize(bytes) {
                        if (bytes === 0) return '0 B';
                        const k = 1024;
                        const sizes = ['B', 'KB', 'MB', 'GB'];
                        const i = Math.floor(Math.log(bytes) / Math.log(k));
                        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                    }

                    function updateFileList() {
                        const fileList = document.getElementById('fileList');
                        const filesCount = document.getElementById('filesCount');
                        
                        filesCount.textContent = selectedFiles.length;
                        
                        if (selectedFiles.length === 0) {
                            fileList.innerHTML = '<div class="file-list-empty">Файлы не выбраны</div>';
                            document.getElementById('cveFileName').textContent = 'Не выбран';
                            document.getElementById('bduFileName').textContent = 'Не выбран';
                            cveFile = null;
                            bduFile = null;
                            return;
                        }
                        
                        let html = '';
                        let cveFound = false;
                        let bduFound = false;
                        
                        selectedFiles.forEach((file, index) => {
                            const fileType = detectFileType(file.name);
                            let typeClass = 'other';
                            let typeLabel = 'Другой';
                            
                            if (fileType === 'cve') {
                                typeClass = 'cve';
                                typeLabel = 'CVE';
                                cveFound = true;
                                cveFile = file;
                            } else if (fileType === 'bdu') {
                                typeClass = 'bdu';
                                typeLabel = 'BDU';
                                bduFound = true;
                                bduFile = file;
                            }
                            
                            const size = formatFileSize(file.size);
                            const icon = getFileIcon(file.name);
                            
                            html += `
                                <div class="file-item">
                                    <div class="file-name">
                                        <span class="file-icon">${icon}</span>
                                        ${file.name}
                                        <span class="file-size">(${size})</span>
                                    </div>
                                    <div style="display: flex; align-items: center; gap: 8px;">
                                        <span class="file-type ${typeClass}">${typeLabel}</span>
                                        <span class="remove-file" onclick="removeFile(${index})">×</span>
                                    </div>
                                </div>
                            `;
                        });
                        
                        fileList.innerHTML = html;
                        
                        document.getElementById('cveFileName').textContent = cveFound ? cveFile.name : 'Не выбран';
                        document.getElementById('bduFileName').textContent = bduFound ? bduFile.name : 'Не выбран';
                    }

                    function removeFile(index) {
                        selectedFiles.splice(index, 1);
                        updateFileList();
                    }

                    function clearAllFiles() {
                        if (selectedFiles.length === 0) return;
                        if (confirm('Очистить все выбранные файлы?')) {
                            selectedFiles = [];
                            cveFile = null;
                            bduFile = null;
                            updateFileList();
                            document.getElementById('restoreNotice').classList.remove('show');
                        }
                    }

                    const fileSelector = document.getElementById('fileSelector');
                    
                    fileSelector.addEventListener('dragover', (e) => {
                        e.preventDefault();
                        fileSelector.classList.add('dragover');
                    });
                    
                    fileSelector.addEventListener('dragleave', (e) => {
                        e.preventDefault();
                        fileSelector.classList.remove('dragover');
                    });
                    
                    fileSelector.addEventListener('drop', (e) => {
                        e.preventDefault();
                        fileSelector.classList.remove('dragover');
                        
                        const files = e.dataTransfer.files;
                        if (files && files.length > 0) {
                            const filesArray = Array.from(files);
                            filesArray.forEach(file => {
                                if (!selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
                                    selectedFiles.push(file);
                                }
                            });
                            updateFileList();
                        }
                    });

                    function displayTaskResult(data) {
                        const resultDiv = document.getElementById('result1');
                        const pre = resultDiv.querySelector('pre');
                        
                        let output = 'Результаты загрузки:\\n\\n';
                        let isError = false;
                        
                        if (data.result) {
                            const result = data.result;
                            if (Array.isArray(result)) {
                                result.forEach((item, index) => {
                                    const type = index === 0 ? 'CVE' : 'BDU';
                                    output += `${type}:\\n`;
                                    if (item.status) {
                                        output += `${item.message}\\n`;
                                        if (item.statistics) {
                                            output += 'Статистика:\\n';
                                            for (const [key, value] of Object.entries(item.statistics)) {
                                                output += `  ${key}: ${value}\\n`;
                                            }
                                        }
                                    } else {
                                        output += `${item.message || 'Ошибка'}\\n`;
                                        isError = true;
                                    }
                                    output += '\\n';
                                });
                            } else if (result.status !== undefined) {
                                output += `Статус: ${result.status ? 'Успешно' : 'Ошибка'}\\n`;
                                output += `Сообщение: ${result.message || 'Нет данных'}\\n`;
                                if (result.statistics) {
                                    output += '\\nСтатистика:\\n';
                                    for (const [key, value] of Object.entries(result.statistics)) {
                                        output += `  ${key}: ${value}\\n`;
                                    }
                                }
                                if (!result.status) isError = true;
                            }
                        } else {
                            output += data.message || 'Нет данных';
                        }
                        
                        pre.textContent = output;
                        resultDiv.classList.add('show');
                        
                        if (isError) {
                            setProgress(100, 'Ошибка', data.message || 'Ошибка выполнения', true);
                        } else {
                            setProgress(100, 'Готово', 'Загрузка завершена успешно', false, true);
                        }
                    }

                    async function checkTaskStatus(taskId) {
                        try {
                            const response = await fetch(`/task_status/${taskId}`);
                            const data = await response.json();
                            
                            console.log('Task status:', data);
                            
                            const resultDiv = document.getElementById('result1');
                            const pre = resultDiv.querySelector('pre');
                            
                            if (data.status === 'completed') {
                                if (statusCheckInterval) {
                                    clearInterval(statusCheckInterval);
                                    statusCheckInterval = null;
                                }
                                
                                displayTaskResult(data);
                                
                                document.getElementById('taskIdDisplay').classList.remove('show');
                                document.getElementById('uploadBtn').disabled = false;
                                document.getElementById('uploadBtn').innerHTML = 'Загрузить в базу';
                                document.getElementById('restoreNotice').classList.remove('show');
                                
                                clearSavedTaskId();
                                isRestored = false;
                                
                            } else if (data.status === 'failed') {
                                if (statusCheckInterval) {
                                    clearInterval(statusCheckInterval);
                                    statusCheckInterval = null;
                                }
                                
                                pre.textContent = `Ошибка: ${data.message || 'Неизвестная ошибка'}`;
                                resultDiv.classList.add('show');
                                setProgress(100, 'Ошибка', data.message || 'Ошибка выполнения', true);
                                
                                document.getElementById('taskIdDisplay').classList.remove('show');
                                document.getElementById('uploadBtn').disabled = false;
                                document.getElementById('uploadBtn').innerHTML = 'Загрузить в базу';
                                document.getElementById('restoreNotice').classList.remove('show');
                                
                                clearSavedTaskId();
                                isRestored = false;
                                
                            } else if (data.status === 'processing') {
                                const progress = data.progress || 0;
                                setProgress(progress, 'Выполняется', data.message || 'Обработка...');
                                document.getElementById('taskIdDisplay').classList.add('show');
                                document.getElementById('taskIdValue').textContent = taskId;
                                
                                if (!isRestored) {
                                    document.getElementById('restoreNotice').classList.add('show');
                                    isRestored = true;
                                }
                                
                                saveTaskId(taskId);
                                
                            } else if (data.status === 'not_found') {
                                document.getElementById('taskIdDisplay').classList.remove('show');
                                document.getElementById('uploadBtn').disabled = false;
                                document.getElementById('uploadBtn').innerHTML = 'Загрузить в базу';
                                document.getElementById('restoreNotice').classList.remove('show');
                                
                                clearSavedTaskId();
                                isRestored = false;
                            }
                        } catch (error) {
                            console.error('Error checking task status:', error);
                        }
                    }

                    function restoreTask() {
                        const savedTaskId = getSavedTaskId();
                        if (!savedTaskId) return false;
                        
                        currentTaskId = savedTaskId;
                        document.getElementById('taskIdDisplay').classList.add('show');
                        document.getElementById('taskIdValue').textContent = currentTaskId;
                        document.getElementById('uploadBtn').disabled = true;
                        document.getElementById('uploadBtn').innerHTML = 'Выполняется...';
                        
                        setIndeterminate('Восстановление', 'Проверка статуса задачи...');
                        
                        if (statusCheckInterval) {
                            clearInterval(statusCheckInterval);
                        }
                        statusCheckInterval = setInterval(() => {
                            checkTaskStatus(currentTaskId);
                        }, 2000);
                        
                        setTimeout(() => checkTaskStatus(currentTaskId), 500);
                        
                        return true;
                    }

                    async function uploadFiles() {
                        const btn = document.getElementById('uploadBtn');
                        const resultDiv = document.getElementById('result1');
                        const pre = resultDiv.querySelector('pre');
                        
                        if (selectedFiles.length === 0) {
                            alert('Пожалуйста, выберите файлы для загрузки');
                            return;
                        }
                        
                        const loadCve = document.getElementById('loadCve').checked;
                        const loadBdu = document.getElementById('loadBdu').checked;
                        
                        if (!loadCve && !loadBdu) {
                            alert('Выберите хотя бы один тип данных для загрузки (CVE или BDU)');
                            return;
                        }
                        
                        if (loadCve && !cveFile) {
                            alert('Выбран файл CVE, но он не определен. Пожалуйста, выберите файл CVE.');
                            return;
                        }
                        
                        if (loadBdu && !bduFile) {
                            alert('Выбран файл BDU, но он не определен. Пожалуйста, выберите файл BDU.');
                            return;
                        }

                        for (let i = 0; i < selectedFiles.length; i++) {
                            const fileType = detectFileType(selectedFiles[i].name);
                            if (fileType === 'other') {
                                alert('Скачивание невозможно. Обнаружены недопустимые файлы.');
                                return;
                            }
                        }
                        
                        resultDiv.classList.add('show');
                        btn.disabled = true;
                        btn.innerHTML = 'Загрузка...';
                        pre.textContent = '';
                        
                        setIndeterminate('Загрузка файлов на сервер', 'Передача файлов...');
                        
                        try {
                            const formData = new FormData();
                            
                            selectedFiles.forEach(file => {
                                formData.append('files', file);
                            });
                            
                            formData.append('cve_filename', loadCve ? cveFile.name : '');
                            formData.append('bdu_filename', loadBdu ? bduFile.name : '');
                            formData.append('load_cve', loadCve ? 'true' : 'false');
                            formData.append('load_bdu', loadBdu ? 'true' : 'false');
                            
                            const response = await fetch('/upload_files', {
                                method: 'POST',
                                body: formData
                            });
                            
                            const data = await response.json();
                            console.log('Response:', data);
                            
                            if (data.task_id) {
                                currentTaskId = data.task_id;
                                document.getElementById('taskIdDisplay').classList.add('show');
                                document.getElementById('taskIdValue').textContent = currentTaskId;
                                
                                saveTaskId(currentTaskId);
                                
                                pre.textContent = `Задача запущена (ID: ${currentTaskId})\\nСтатус будет обновляться автоматически...`;
                                
                                if (statusCheckInterval) {
                                    clearInterval(statusCheckInterval);
                                }
                                statusCheckInterval = setInterval(() => {
                                    checkTaskStatus(currentTaskId);
                                }, 2000);
                                
                                setTimeout(() => checkTaskStatus(currentTaskId), 500);
                                
                                setProgress(10, 'Задача запущена', 'Обработка файлов...');
                                
                            } else {
                                let output = JSON.stringify(data, null, 2);
                                pre.textContent = output;
                                
                                if (data.status === false) {
                                    setProgress(100, 'Ошибка', data.message || 'Ошибка', true);
                                } else {
                                    setProgress(100, 'Готово', 'Загрузка завершена', false, true);
                                }
                                
                                btn.disabled = false;
                                btn.innerHTML = 'Загрузить в базу';
                            }
                            
                        } catch (error) {
                            console.error('Error:', error);
                            pre.textContent = 'Ошибка: ' + error.message;
                            setProgress(100, 'Ошибка', 'Не удалось загрузить файлы', true);
                            btn.disabled = false;
                            btn.innerHTML = 'Загрузить в базу';
                        }
                    }

                    async function callAPI(method, endpoint, resultId) {
                        const resultDiv = document.getElementById(resultId);
                        const pre = resultDiv.querySelector('pre');
                        const button = resultDiv.parentElement.querySelector('.btn');

                        resultDiv.classList.add('show');
                        if (button) {
                            button.disabled = true;
                            button.innerHTML = 'Загрузка...';
                        }

                        pre.textContent = '';
                        setIndeterminate('Выполняется запрос', 'Соединение с сервером…');

                        try {
                            const response = await fetch(endpoint);
                            const data = await response.json();
                            
                            let output = '';
                            if (data.status && data.config) {
                                output = 'Текущая конфигурация:\\n\\n';
                                for (const [key, value] of Object.entries(data.config)) {
                                    output += `  ${key}: ${value || '(не задано)'}\\n`;
                                }
                                setProgress(100, 'Готово', 'Конфигурация загружена', false, true);
                            } else {
                                output = JSON.stringify(data, null, 2);
                                setProgress(100, 'Ошибка', 'Ошибка получения конфигурации', true);
                            }
                            pre.textContent = output;
                            
                        } catch (error) {
                            console.error('Error:', error);
                            pre.textContent = 'Ошибка: ' + error.message;
                            setProgress(100, 'Ошибка', 'Не удалось получить конфигурацию', true);
                        } finally {
                            if (button) {
                                button.disabled = false;
                                button.innerHTML = 'Показать конфигурацию';
                            }
                        }
                    }

                    async function loadConfig() {
                        try {
                            const response = await fetch('/config');
                            const data = await response.json();
                            if (data.status && data.config) {
                                // Не устанавливаем имена файлов при загрузке страницы
                                // Оставляем "Не выбран" по умолчанию
                                console.log('Config loaded:', data.config);
                            }
                        } catch (error) {
                            console.error('Error loading config:', error);
                        }
                    }

                    document.addEventListener('DOMContentLoaded', function() {
                        console.log('Page loaded - GET request');
                        
                        // Сбрасываем состояние файлов при загрузке страницы
                        selectedFiles = [];
                        cveFile = null;
                        bduFile = null;
                        updateFileList();
                        
                        const restored = restoreTask();
                        
                        if (!restored) {
                            loadConfig();
                            setProgress(0, 'Ожидание', 'Готов к работе');
                        }
                    });
                </script>
            </body>
        </html>
    """
    return HTMLResponse(content=html_content)

# ===== API ENDPOINTS FOR BDU =====

@router.get("/api/bdu/list", summary="Получить список BDU")
async def get_bdu_list(
    limit: int = 100,
    skip: int = 0
):
    """
    Получить список BDU уязвимостей из MongoDB
    """
    try:
        bdu_data = list(bdu_collection.find({})
            .sort([("imported_at", -1)])
            .skip(skip)
            .limit(limit))
        
        # Преобразуем для JSON
        for item in bdu_data:
            if '_id' in item:
                pass  # _id уже строка
            if 'imported_at' in item and hasattr(item['imported_at'], 'isoformat'):
                item['imported_at'] = item['imported_at'].isoformat()
        
        return {
            "status": True,
            "data": bdu_data,
            "count": len(bdu_data)
        }
    except Exception as e:
        return {
            "status": False,
            "message": str(e)
        }

@router.get("/api/bdu/{bdu_id}", summary="Получить BDU по ID")
async def get_bdu_by_id(bdu_id: str):
    """
    Получить BDU уязвимость по ID
    """
    try:
        item = bdu_collection.find_one({"_id": bdu_id})
        if not item:
            raise HTTPException(status_code=404, detail="BDU not found")
        
        return {
            "status": True,
            "data": item
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/api/bdu/{bdu_id}", summary="Удалить BDU по ID")
async def delete_bdu(bdu_id: str):
    """
    Удалить BDU уязвимость по ID
    """
    try:
        result = bdu_collection.delete_one({"_id": bdu_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="BDU not found")
        
        return {
            "status": True,
            "message": f"BDU {bdu_id} удален"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/api/bdu/clear", summary="Удалить все BDU")
async def clear_all_bdu():
    """
    Удалить все BDU записи
    """
    try:
        result = bdu_collection.delete_many({})
        return {
            "status": True,
            "message": f"Удалено {result.deleted_count} записей"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ===== Функции для работы с ZIP архивами =====

async def extract_xml_from_zip(zip_path: str, extract_dir: str) -> list:
    """
    Извлекает все XML файлы из ZIP архива и возвращает список путей к ним
    """
    xml_files = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Извлекаем все файлы
            zip_ref.extractall(extract_dir)
            
            # Ищем XML файлы
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.lower().endswith('.xml'):
                        xml_files.append(os.path.join(root, file))
                        print(f"Найден XML файл в архиве: {file}")
    
    except zipfile.BadZipFile as e:
        print(f"Ошибка: Файл не является ZIP архивом: {e}")
        raise
    except Exception as e:
        print(f"Ошибка при распаковке ZIP: {e}")
        raise
    
    return xml_files

async def process_zip_bdu(zip_path: str, temp_dir: str) -> dict:
    """
    Обрабатывает ZIP архив с BDU данными
    """
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    
    try:
        # Извлекаем XML файлы из ZIP
        xml_files = await extract_xml_from_zip(zip_path, extract_dir)
        
        if not xml_files:
            return {
                "status": False,
                "message": "В ZIP архиве не найдено XML файлов"
            }
        
        # Обрабатываем каждый XML файл
        results = []
        total_processed = 0
        
        for xml_file in xml_files:
            try:
                result = await clone_bdu_xml_in_mongo(xml_file)
                if result.get('status', False):
                    total_processed += 1
                results.append(result)
            except Exception as e:
                results.append({
                    "status": False,
                    "message": f"Ошибка обработки {os.path.basename(xml_file)}: {str(e)}"
                })
        
        # Формируем общий результат
        success_count = sum(1 for r in results if r.get('status', False))
        
        return {
            "status": success_count > 0,
            "message": f"Обработано {len(xml_files)} XML файлов из ZIP архива. Успешно: {success_count}",
            "statistics": {
                "total_files": len(xml_files),
                "successful": success_count,
                "failed": len(xml_files) - success_count
            },
            "details": results
        }
        
    except Exception as e:
        return {
            "status": False,
            "message": f"Ошибка обработки ZIP архива: {str(e)}"
        }
    finally:
        # Очищаем временные файлы
        try:
            shutil.rmtree(extract_dir)
        except:
            pass

# ===== UPLOAD FUNCTIONS =====

@router.post("/upload_files", summary="Загрузить файлы CVE и BDU в базу данных", tags=["CVE"])
async def upload_files(
    background_tasks: BackgroundTasks,
    files: list[UploadFile] = File(...),
    cve_filename: str = Form(""),
    bdu_filename: str = Form(""),
    load_cve: str = Form("true"),
    load_bdu: str = Form("true")
):
    """
    Загружает выбранные файлы CVE и/или BDU в MongoDB в фоновом режиме.
    Поддерживает BDU файлы в форматах XML и ZIP (автоматически распаковывает ZIP).
    """
    task_id = str(uuid.uuid4())
    
    load_cve_bool = load_cve.lower() == "true"
    load_bdu_bool = load_bdu.lower() == "true"
    
    if not load_cve_bool and not load_bdu_bool:
        return {
            "status": False,
            "message": "Не выбран ни один тип данных для загрузки"
        }
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        saved_files = {}
        for file in files:
            file_path = os.path.join(temp_dir, file.filename)
            with open(file_path, "wb") as f:
                shutil.copyfileobj(file.file, f)
            saved_files[file.filename] = file_path
        
        task_statuses[task_id] = {
            "status": "processing",
            "progress": 0,
            "message": "Начало обработки...",
            "result": None,
            "temp_dir": temp_dir,
            "saved_files": saved_files
        }
        
        background_tasks.add_task(
            process_files,
            task_id,
            saved_files,
            cve_filename,
            bdu_filename,
            load_cve_bool,
            load_bdu_bool,
            temp_dir
        )
        
        return {
            "task_id": task_id,
            "status": "processing",
            "message": "Задача запущена в фоновом режиме"
        }
        
    except Exception as e:
        try:
            shutil.rmtree(temp_dir)
        except:
            pass
        
        return {
            "status": False,
            "message": f"Ошибка загрузки файлов: {str(e)}"
        }

async def process_files(
    task_id: str,
    saved_files: dict,
    cve_filename: str,
    bdu_filename: str,
    load_cve: bool,
    load_bdu: bool,
    temp_dir: str
):
    """
    Фоновая обработка файлов с поддержкой ZIP архивов для BDU
    """
    try:
        results = []
        
        task_statuses[task_id]["message"] = "Начинаем загрузку..."
        task_statuses[task_id]["progress"] = 10
        
        # Обработка CVE
        if load_cve:
            task_statuses[task_id]["message"] = "Загрузка CVE..."
            task_statuses[task_id]["progress"] = 30
            
            cve_file_path = saved_files.get(cve_filename)
            if cve_file_path and os.path.exists(cve_file_path):
                try:
                    result = await clone_cve_in_mongo(cve_file_path)
                    results.append(result)
                    task_statuses[task_id]["message"] = "CVE загружен"
                    task_statuses[task_id]["progress"] = 50
                except Exception as e:
                    results.append({
                        "status": False,
                        "message": f"Ошибка загрузки CVE: {str(e)}"
                    })
                    task_statuses[task_id]["message"] = f"Ошибка CVE: {str(e)}"
            else:
                results.append({
                    "status": False,
                    "message": f"Файл CVE '{cve_filename}' не найден"
                })
                task_statuses[task_id]["message"] = "Файл CVE не найден"
        
        # Обработка BDU
        if load_bdu:
            task_statuses[task_id]["message"] = "Загрузка BDU..."
            task_statuses[task_id]["progress"] = 60
            
            bdu_file_path = saved_files.get(bdu_filename)
            if bdu_file_path and os.path.exists(bdu_file_path):
                try:
                    # Проверяем, является ли файл ZIP архивом
                    file_extension = os.path.splitext(bdu_filename)[1].lower()
                    
                    if file_extension == '.zip':
                        # Обрабатываем ZIP архив
                        task_statuses[task_id]["message"] = "Распаковка ZIP архива BDU..."
                        task_statuses[task_id]["progress"] = 70
                        
                        result = await process_zip_bdu(bdu_file_path, temp_dir)
                        results.append(result)
                        
                        task_statuses[task_id]["message"] = f"BDU из ZIP обработан: {result.get('message', '')}"
                        task_statuses[task_id]["progress"] = 85
                    else:
                        # Обрабатываем XML файл напрямую
                        result = await clone_bdu_xml_in_mongo(bdu_file_path)
                        results.append(result)
                        task_statuses[task_id]["message"] = "BDU загружен"
                        task_statuses[task_id]["progress"] = 85
                        
                except Exception as e:
                    results.append({
                        "status": False,
                        "message": f"Ошибка загрузки BDU: {str(e)}"
                    })
                    task_statuses[task_id]["message"] = f"Ошибка BDU: {str(e)}"
            else:
                results.append({
                    "status": False,
                    "message": f"Файл BDU '{bdu_filename}' не найден"
                })
                task_statuses[task_id]["message"] = "Файл BDU не найден"
        
        # Сохраняем конфигурацию в Redis
        if load_cve and cve_filename:
            await redis_client.hset("my_config", "filename_cve", cve_filename)
        if load_bdu and bdu_filename:
            await redis_client.hset("my_config", "filename_bdu", bdu_filename)
        await redis_client.hset("my_config", "download_path", temp_dir)
        
        task_statuses[task_id]["status"] = "completed"
        task_statuses[task_id]["progress"] = 100
        task_statuses[task_id]["message"] = "Загрузка завершена"
        task_statuses[task_id]["result"] = results if len(results) > 1 else results[0] if results else None
        
    except Exception as e:
        task_statuses[task_id]["status"] = "failed"
        task_statuses[task_id]["message"] = f"Ошибка: {str(e)}"
        task_statuses[task_id]["progress"] = 100
        
    finally:
        try:
            shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"Error cleaning temp dir: {e}")

@router.get("/task_status/{task_id}", summary="Получить статус задачи", tags=["CVE"])
async def get_task_status(task_id: str):
    """
    Получить статус фоновой задачи
    """
    task = task_statuses.get(task_id)
    
    if not task:
        return {
            "status": "not_found",
            "message": "Задача не найдена"
        }
    
    return {
        "status": task["status"],
        "progress": task.get("progress", 0),
        "message": task.get("message", ""),
        "result": task.get("result") if task["status"] in ["completed", "failed"] else None
    }

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