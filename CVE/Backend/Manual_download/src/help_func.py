import tempfile
from pathlib import Path
import json
import zipfile
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
from lxml import etree
from datetime import datetime
import os
import shutil

redis_client = redis.Redis(
    host='my-redis',
    port=6379,
    decode_responses=True,
    socket_connect_timeout=5
)

task_statuses = {}

ATTR_SIMPLE = [
    "identifier", "name", "description", "identify_date", "publication_date",
    "last_upd_date", "severity", "solution", "vul_status", "exploit_status",
    "fix_status", "other", "vul_incident", "vul_class", "vul_state", "vul_elimination"
]

ATTR_LIST = {
    "vulnerable_software": "soft",
    "environment": "os",
    "cwes": "cwe",
    "identifiers": "identifier"
}

async def init_mongo():
    try:
        await redis_client.ping()
        name_base = await redis_client.hget("my_config", "name_base") or "cve_db"
        if not await redis_client.hget("my_config", "name_base"):
            await redis_client.hset("my_config", "name_base", name_base)
        client = AsyncIOMotorClient("mongodb://mongodb:27017/")
        await client.admin.command('ping')
        return client[name_base]
    except Exception as e:
        print(f"Ошибка подключения к БД: {e}")
        client = AsyncIOMotorClient("mongodb://mongodb:27017/")
        return client["cve_db"]

def parse_bdu_vul(vul):
    doc = {}
    for attr in ATTR_SIMPLE:
        value = vul.findtext(attr)
        if value and value.strip():
            if attr == "identifier":
                doc["_id"] = value
            else:
                doc[attr] = value
    for key, tag in ATTR_LIST.items():
        elements = vul.findall(f"{key}/{tag}")
        values = [e.text.strip() for e in elements if e.text and e.text.strip()]
        if values:
            if key == "identifiers":
                doc["identifiers_CVE"] = values
            else:
                doc[key] = values
    cvss = vul.findtext("cvss/vector")
    if cvss and cvss.strip():
        doc["cvss"] = cvss
    sources = vul.findtext("sources")
    if sources and sources.strip():
        doc["sources"] = sources.split()
    doc["imported_at"] = datetime.now()
    return doc

async def clone_bdu_xml_in_mongo(file_path):
    """Принимает полный путь к файлу"""
    path = Path(file_path)
    tree = etree.parse(str(path))
    vulnerabilities = [parse_bdu_vul(v) for v in tree.getroot().findall("vul")]
    
    base = await init_mongo()
    collection = base["BDU"]
    stats = {"total": 0, "created": 0, "updated": 0, "errors": 0}
    
    for elem in vulnerabilities:
        if "_id" not in elem:
            stats["errors"] += 1
            continue
        try:
            result = await collection.update_one({"_id": elem["_id"]}, {"$set": elem}, upsert=True)
            stats["total"] += 1
            if result.upserted_id:
                stats["created"] += 1
            else:
                stats["updated"] += 1
        except Exception as e:
            print(f"Ошибка: {e}")
            stats["errors"] += 1
    
    if stats["total"] == 0:
        return {"status": False, "message": "Файлов с данными о БДУ не обнаружено."}
    return {
        "status": True,
        "message": "Файлы успешно добавлены!",
        "statistics": {
            "Всего файлов": stats["total"],
            "Новых документов": stats["created"],
            "Обновлённых документов": stats["updated"],
            "Ошибок": stats["errors"]
        }
    }

async def clone_cve_in_mongo(zip_path):
    """Принимает полный путь к ZIP файлу"""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        extract_path = temp_path / "extracted"
        
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_path)
        
        base = await init_mongo()
        collection = base["CVE"]
        stats = {"total": 0, "created": 0, "updated": 0, "errors": 0}
        
        for file_path in extract_path.rglob("CVE*.json"):
            if not file_path.is_file():
                continue
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                cve_id = data.get("cveMetadata", {}).get("cveId")
                if not cve_id:
                    stats["errors"] += 1
                    continue
                result = await collection.update_one(
                    {"cveMetadata.cveId": cve_id},
                    {"$set": data},
                    upsert=True
                )
                stats["total"] += 1
                if result.upserted_id:
                    stats["created"] += 1
                else:
                    stats["updated"] += 1
            except Exception as e:
                print(f"Ошибка: {e}")
                stats["errors"] += 1
        
        if stats["total"] == 0:
            return {"status": False, "message": "JSON-файлов с данными о CVE не обнаружено."}
        return {
            "status": True,
            "message": "Файлы успешно добавлены!",
            "statistics": {
                "Всего файлов": stats["total"],
                "Новых документов": stats["created"],
                "Обновлённых документов": stats["updated"],
                "Ошибок": stats["errors"]
            }
        }

async def extract_xml_from_zip(zip_path, extract_dir):
    xml_files = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    if file.lower().endswith('.xml'):
                        xml_files.append(os.path.join(root, file))
    except Exception as e:
        print(f"Ошибка распаковки: {e}")
        raise
    return xml_files

async def process_zip_bdu(zip_path, temp_dir):
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    try:
        xml_files = await extract_xml_from_zip(zip_path, extract_dir)
        if not xml_files:
            return {"status": False, "message": "В ZIP архиве не найдено XML файлов"}
        
        results = []
        for xml_file in xml_files:
            try:
                result = await clone_bdu_xml_in_mongo(xml_file)
                results.append(result)
            except Exception as e:
                results.append({"status": False, "message": f"Ошибка: {str(e)}"})
        
        success = sum(1 for r in results if r.get("status", False))
        return {
            "status": success > 0,
            "message": f"Обработано {len(xml_files)} XML файлов. Успешно: {success}",
            "statistics": {
                "total_files": len(xml_files),
                "successful": success,
                "failed": len(xml_files) - success
            },
            "details": results
        }
    except Exception as e:
        return {"status": False, "message": f"Ошибка: {str(e)}"}
    finally:
        try:
            shutil.rmtree(extract_dir)
        except:
            pass

async def process_files(task_id, saved_files, cve_filename, bdu_filename, load_cve, load_bdu, temp_dir):
    try:
        results = []
        task_statuses[task_id]["message"] = "Начинаем загрузку..."
        task_statuses[task_id]["progress"] = 10
        
        if load_cve:
            task_statuses[task_id]["message"] = "Загрузка CVE..."
            task_statuses[task_id]["progress"] = 30
            cve_path = saved_files.get(cve_filename)
            if cve_path and os.path.exists(cve_path):
                try:
                    task_statuses[task_id]["progress"] = 40
                    result = await clone_cve_in_mongo(cve_path)  # Передаем полный путь
                    results.append(result)
                    task_statuses[task_id]["message"] = "CVE загружен"
                    task_statuses[task_id]["progress"] = 50
                except Exception as e:
                    results.append({"status": False, "message": f"Ошибка CVE: {str(e)}"})
                    task_statuses[task_id]["message"] = f"Ошибка CVE: {str(e)}"
            else:
                results.append({"status": False, "message": f"Файл CVE '{cve_filename}' не найден"})
                task_statuses[task_id]["message"] = "Файл CVE не найден"
        
        if load_bdu:
            task_statuses[task_id]["message"] = "Загрузка BDU..."
            task_statuses[task_id]["progress"] = 60
            bdu_path = saved_files.get(bdu_filename)
            if bdu_path and os.path.exists(bdu_path):
                try:
                    ext = os.path.splitext(bdu_filename)[1].lower()
                    if ext == '.zip':
                        task_statuses[task_id]["progress"] = 70
                        result = await process_zip_bdu(bdu_path, temp_dir)
                    else:
                        result = await clone_bdu_xml_in_mongo(bdu_path)  # Передаем полный путь
                    results.append(result)
                    task_statuses[task_id]["message"] = "BDU загружен"
                    task_statuses[task_id]["progress"] = 85
                except Exception as e:
                    results.append({"status": False, "message": f"Ошибка BDU: {str(e)}"})
                    task_statuses[task_id]["message"] = f"Ошибка BDU: {str(e)}"
            else:
                results.append({"status": False, "message": f"Файл BDU '{bdu_filename}' не найден"})
                task_statuses[task_id]["message"] = "Файл BDU не найден"
        
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
        except:
            pass