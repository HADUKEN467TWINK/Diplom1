from fastapi import APIRouter, File, UploadFile, Form, BackgroundTasks
from src.help_func import task_statuses, process_files
from fastapi.responses import HTMLResponse, FileResponse
import os
import tempfile
import shutil
import uuid

router = APIRouter()

@router.get("/", response_class=HTMLResponse)
async def home():
    return FileResponse("templates/index.html")

@router.post("/upload_files")
async def upload_files(
    background_tasks: BackgroundTasks,
    files: list[UploadFile] = File(...),
    cve_filename: str = Form(""),
    bdu_filename: str = Form(""),
    load_cve: str = Form("true"),
    load_bdu: str = Form("true")
):
    task_id = str(uuid.uuid4())
    load_cve_bool = load_cve.lower() == "true"
    load_bdu_bool = load_bdu.lower() == "true"
    
    if not load_cve_bool and not load_bdu_bool:
        return {"status": False, "message": "Не выбран ни один тип данных для загрузки"}
    
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
            task_id, saved_files, cve_filename, bdu_filename,
            load_cve_bool, load_bdu_bool, temp_dir
        )
        
        return {"task_id": task_id, "status": "processing", "message": "Задача запущена"}
        
    except Exception as e:
        try:
            shutil.rmtree(temp_dir)
        except:
            pass
        return {"status": False, "message": f"Ошибка: {str(e)}"}

@router.get("/task_status/{task_id}")
async def get_task_status(task_id: str):
    task = task_statuses.get(task_id)
    if not task:
        return {"status": "not_found", "message": "Задача не найдена"}
    return {
        "status": task["status"],
        "progress": task.get("progress", 0),
        "message": task.get("message", ""),
        "result": task.get("result") if task["status"] in ["completed", "failed"] else None
    }