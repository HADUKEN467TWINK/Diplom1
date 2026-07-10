import tempfile
from pathlib import Path
import requests
import json
import zipfile
from lxml import etree
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
from datetime import datetime

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
    return base

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

async def download_url(repo_url: str, temp_path: Path) -> Path:
    """Скачивает файл и возвращает путь к нему"""
    temp_path.mkdir(parents=True, exist_ok=True)
    
    if '.zip' in repo_url.lower():
        zip_path = temp_path / "download_cve.zip"
    else:
        zip_path = temp_path / "download_bdu.xml"
    
    # Создаем сессию с отключенной проверкой SSL
    session = requests.Session()
    session.verify = False
    
    try:
        response = session.get(repo_url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(zip_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        if zip_path.exists():
            print(f"Файл скачан: {zip_path}, размер: {zip_path.stat().st_size} байт")
            return zip_path
        else:
            raise Exception(f"Файл не был создан: {zip_path}")
            
    except Exception as e:
        raise Exception(f"Ошибка при скачивании: {str(e)}")

async def update_cve_in_mongo(update_url: str, use_browser: bool = False):
    """
    Обновляет базу данных CVE из указанного URL
    
    Args:
        update_url: URL для скачивания
        use_browser: Если True - открывает ссылку в браузере для ручного скачивания,
                    Если False - скачивает напрямую через код
    """
    with tempfile.TemporaryDirectory() as temp_file:
        temp_path = Path(temp_file)
        
        if use_browser:
            # Режим через браузер
            import webbrowser
            import shutil
            
            print(f"Открываю ссылку в браузере: {update_url}")
            webbrowser.open(update_url)
            
            # Создаем поддиректорию для ручной загрузки
            manual_download_path = temp_path / "manual_download"
            manual_download_path.mkdir(exist_ok=True)
            
            print(f"\nПожалуйста, скачайте файл вручную в следующую директорию:")
            print(f"  {manual_download_path.absolute()}")
            print("\nОжидаемые имена файлов:")
            print("  - download_cve.zip (для CVE)")
            print("\nПосле скачивания файла нажмите Enter для продолжения...")
            
            input()
            
            # Ищем скачанный файл
            downloaded_files = list(manual_download_path.glob("*"))
            if not downloaded_files:
                raise Exception("Файл не найден в директории для ручной загрузки")
            
            # Берем первый найденный файл
            zip_path = downloaded_files[0]
            print(f"Найден файл: {zip_path.name}, размер: {zip_path.stat().st_size} байт")
            
            # Перемещаем файл в основную временную директорию
            target_path = temp_path / zip_path.name
            shutil.move(str(zip_path), str(target_path))
            zip_path = target_path
            
        else:
            # Прямое скачивание
            zip_path = await download_url(update_url, temp_path)
        
        extract_path = temp_path / "extracted"
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_path)

        base = await init_mongo()
        collection_cve = base["CVE"]
        successful_creates = 0
        successful_updates = 0
        errors = 0
        
        for file_path in extract_path.rglob("CVE*.json"):
            if file_path.is_file():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        json_data = json.load(f)
                    cve_id = json_data.get("cveMetadata", {}).get("cveId")
                    if not cve_id:
                        print(f"Ошибка: CVE ID не найден в файле {file_path.name}")
                        errors += 1
                        continue
                    result = await collection_cve.update_one(
                        {"cveMetadata.cveId": cve_id},
                        {"$set": json_data},
                        upsert=True
                    )

                    if result.upserted_id is not None:
                        successful_creates += 1
                    elif result.modified_count > 0:
                        successful_updates += 1

                except Exception as e:
                    print(f"Ошибка в {file_path.name}: {e}")
                    errors += 1
                    
        total_processed = successful_updates + successful_creates
        if total_processed == 0:
            return {
                "status": False,
                "message": "JSON-файлов с новыми данными о CVE не обнаружено."
            }
        return {
            "status": True,
            "message": "База данных успешно обновлена!",
            "statistics": {
                "Всего обработано файлов": total_processed,
                "Обновлённых документов": successful_updates,
                "Новых документов": successful_creates,
                "Ошибок": errors
            }
        }


async def update_bdu_in_mongo(update_url: str, use_browser: bool = False):
    """
    Обновляет базу данных BDU из указанного URL
    
    Args:
        update_url: URL для скачивания
        use_browser: Если True - открывает ссылку в браузере для ручного скачивания,
                    Если False - скачивает напрямую через код
    """
    len_document = 20
    excp_change = True
    with tempfile.TemporaryDirectory() as temp_file:
        temp_path = Path(temp_file)
        
        if use_browser:
            # Режим через браузер
            import webbrowser
            import shutil
            
            print(f"Открываю ссылку в браузере: {update_url}")
            webbrowser.open(update_url)
            
            # Создаем поддиректорию для ручной загрузки
            manual_download_path = temp_path / "manual_download"
            manual_download_path.mkdir(exist_ok=True)
            
            print(f"\nПожалуйста, скачайте файл вручную в следующую директорию:")
            print(f"  {manual_download_path.absolute()}")
            print("\nОжидаемые имена файлов:")
            print("  - download_bdu.xml (для BDU)")
            print("\nПосле скачивания файла нажмите Enter для продолжения...")
            
            input()
            
            # Ищем скачанный файл
            downloaded_files = list(manual_download_path.glob("*"))
            if not downloaded_files:
                raise Exception("Файл не найден в директории для ручной загрузки")
            
            # Берем первый найденный файл
            downloaded_path = downloaded_files[0]
            print(f"Найден файл: {downloaded_path.name}, размер: {downloaded_path.stat().st_size} байт")
            
            # Перемещаем файл в основную временную директорию
            target_path = temp_path / downloaded_path.name
            shutil.move(str(downloaded_path), str(target_path))
            downloaded_path = target_path
            
        else:
            # Прямое скачивание
            downloaded_path = await download_url(update_url, temp_path)
        
        if downloaded_path.suffix.lower() == '.zip':
            # Обработка ZIP
            zip_path = downloaded_path
            extract_path = temp_path / "extracted"
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_path)
            xml_files = next(extract_path.rglob("*.xml"), None)
        else:
            xml_files = downloaded_path
            
        if not xml_files:
            return {"status": False, "message": "XML файлов не найдено"}
            
        tree = etree.parse(xml_files)
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
                if result.upserted_id is not None:
                    successful_creates += 1
                    total_files += 1
                else:
                    successful_updates += 1
            except Exception as e:
                print(f"Ошибка при вставке {elem.get('_id', 'unknown')}: {e}")
                errors += 1
                
        if total_files == 0 and successful_updates == 0:
            return {
                "status": False,
                "message": "Файлов с данными о БДУ не обнаружено."
            }
        elif total_files == 0 and successful_updates != 0:
            return {
                "status": True,
                "message": "Файлов с данными о БДУ не обнаружено.",
                "statistics": {
                    "Обновлённых документов": successful_updates,
                }
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
                    "Предупреждение": "Структура файлов БДУ могла быть изменена авторами. Проверьте структуру полей в файлах."
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