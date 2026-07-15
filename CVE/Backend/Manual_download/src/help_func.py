import tempfile
from pathlib import Path
import json
import zipfile
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
from lxml import etree
from datetime import datetime
import redis.asyncio as redis
import os
import shutil

redis_client = redis.Redis(
    host='my-redis',
    port=6379,
    decode_responses=True,
    socket_connect_timeout=5
)

task_statuses = {}

def atr_simple_none(doc: dict, text: str, vul):
    atr = vul.findtext(text)
    if atr and atr.strip():
        if text == "identifier":
            doc["_id"] = atr
            return None
    doc[text] = atr
    return None

atributs_simple = [
            "identifier", "name", "description", "identify_date", "publication_date", "last_upd_date", "severity",
            "solution", "vul_status", "exploit_status", "fix_status", "other", "vul_incident", "vul_class", "vul_state",
            "vul_elimination"
]

atributs_list = {
            "vulnerable_software": "soft",
            "environment": "os",
            "cwes": "cwe",
            "identifiers": "identifier"
}

async def init_mongo():
    """Инициализация MongoDB с данными из Redis"""
    try:
        # Проверяем подключение к Redis
        await redis_client.ping()
        
        # Получаем имя базы данных из Redis
        name_base = await redis_client.hget("my_config", "name_base")
        
        # Если имя базы не задано, используем значение по умолчанию
        if not name_base:
            name_base = "cve_db"
            # Сохраняем значение по умолчанию в Redis
            await redis_client.hset("my_config", "name_base", name_base)
        
        mongodb_url = "mongodb://mongodb:27017/"
        mongo_client = AsyncIOMotorClient(mongodb_url)
        
        # Проверяем подключение к MongoDB
        await mongo_client.admin.command('ping')
        
        base = mongo_client[name_base]
        return base
    except redis.ConnectionError as e:
        print(f"Ошибка подключения к Redis: {e}")
        # Используем значения по умолчанию
        mongodb_url = "mongodb://my-mongo:27017/"
        mongo_client = AsyncIOMotorClient(mongodb_url)
        base = mongo_client["cve_db"]
        return base
    except Exception as e:
        print(f"Ошибка инициализации MongoDB: {e}")
        # Используем значения по умолчанию
        mongodb_url = "mongodb://mongodb:27017/"
        mongo_client = AsyncIOMotorClient(mongodb_url)
        base = mongo_client["cve_db"]
        return base

async def clone_bdu_xml_in_mongo(filename_bdu_xml: str):
    excp_change = True
    len_document = 20
    UPLOAD_DIR = Path("/app/__download_file__")
    path = UPLOAD_DIR / filename_bdu_xml
    tree = etree.parse(str(path))
    root = tree.getroot()
    vulnerabilities = []
    vul_all = root.findall("vul")
    for vul in vul_all:
        doc = {}
        for i in atributs_simple:
            atr_simple_none(doc, i, vul)
        for key, i in atributs_list.items():
            elements = vul.findall(f"{key}/{i}")
            true_list = []
            for elem in elements:
                if elem.text and elem.text.strip():
                    true_list.append(elem.text.strip())
            if true_list:
                if key == "identifiers":
                    doc["identifiers_CVE"] = true_list
                    continue
                doc[key] = true_list
        vector = vul.findtext("cvss/vector")
        if vector and vector.strip():
            doc["cvss"] = vector
        sources = vul.findtext("sources")
        if sources and sources.strip():
            doc["sources"] = sources.split()
        doc["imported_at"] = datetime.now()
        vulnerabilities.append(doc)
        if len_document == len(vulnerabilities):
            excp_change = False

    base = await init_mongo()
    collection_bdu = base["BDU"]
    total_files = 0
    successful_creates = 0
    successful_updates = 0
    errors = 0
    for elem in vulnerabilities:
        try:
            if "_id" not in elem:
                errors += 1
                continue
            result = await collection_bdu.update_one(
                {"_id": elem["_id"]},
                {"$set": elem},
                upsert=True
            )
            total_files += 1
            if result.upserted_id is not None:
                successful_creates += 1
            else:
                successful_updates += 1
        except Exception as e:
            print(f"Ошибка при вставке {elem.get('_id', 'unknown')}: {e}")
            errors += 1
    if total_files == 0:
        return {
            "status": False,
            "message": "Файлов с данными о БДУ не обнаружено."
        }
    if excp_change:
        return {
            "status": True,
            "message": "Файлы успешно добавлены!",
            "statistics": {
                "Всего файлов": total_files,
                "Новых документов": successful_creates,
                "Обновлённых документов": successful_updates,
                "Ошибок": errors,
            }
        }
    return {
        "status": True,
        "message": "Файлы успешно добавлены!",
        "statistics": {
            "Всего файлов": total_files,
            "Новых документов": successful_creates,
            "Обновлённых документов": successful_updates,
            "Ошибок": errors
        }
    }

async def clone_cve_in_mongo(filename: str):
    with tempfile.TemporaryDirectory() as temp_file:
        temp_path = Path(temp_file)
        UPLOAD_DIR = Path("/app/__download_file__")
        zip_path = UPLOAD_DIR / filename
        extract_path = temp_path / "extracted"
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_path)

        base = await init_mongo()
        collection_cve = base["CVE"]
        total_files = 0
        successful_creates = 0
        successful_updates = 0
        errors = 0
        for file_path in extract_path.rglob("CVE*.json"):
            if file_path.is_file():
                total_files += 1
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        json_data = json.load(f)
                    cve_id = json_data.get("cveMetadata", {}).get("cveId")
                    if not cve_id:
                        errors += 1
                        continue
                    result = await collection_cve.update_one(
                        {"cveMetadata.cveId": cve_id},
                        {"$set": json_data},
                        upsert=True
                    )

                    if result.upserted_id is not None:
                        successful_creates += 1
                    else:
                        successful_updates += 1

                except Exception as e:
                    print(f"Ошибка в {file_path.name}: {e}")
                    errors += 1
        if total_files == 0:
            return {
                "status": False,
                "message": "JSON-файлов с данными о CVE не обнаружено."
            }
        return {
            "status": True,
            "message": "Файлы успешно добавлены!",
            "statistics": {
                "Всего файлов": total_files,
                "Новых документов": successful_creates,
                "Обновлённых документов": successful_updates,
                "Ошибок": errors
            }
        }

async def extract_xml_from_zip(zip_path: str, extract_dir: str) -> list:
    """
    Извлекает все XML файлы из ZIP архива и возвращает список путей к ним
    """
    xml_files = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
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
        xml_files = await extract_xml_from_zip(zip_path, extract_dir)
        if not xml_files:
            return {
                "status": False,
                "message": "В ZIP архиве не найдено XML файлов"
            }
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
        try:
            shutil.rmtree(extract_dir)
        except:
            pass

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
        if load_cve:
            task_statuses[task_id]["message"] = "Загрузка CVE..."
            task_statuses[task_id]["progress"] = 30
            cve_file_path = saved_files.get(cve_filename)
            if cve_file_path and os.path.exists(cve_file_path):
                try:
                    task_statuses[task_id]["message"] = "Распаковка ZIP архива CVE..."
                    task_statuses[task_id]["progress"] = 40
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
        if load_bdu:
            task_statuses[task_id]["message"] = "Загрузка BDU..."
            task_statuses[task_id]["progress"] = 60
            bdu_file_path = saved_files.get(bdu_filename)
            if bdu_file_path and os.path.exists(bdu_file_path):
                try:
                    file_extension = os.path.splitext(bdu_filename)[1].lower()
                    if file_extension == '.zip':
                        task_statuses[task_id]["message"] = "Распаковка ZIP архива BDU..."
                        task_statuses[task_id]["progress"] = 70
                        result = await process_zip_bdu(bdu_file_path, temp_dir)
                        results.append(result)
                    else:
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