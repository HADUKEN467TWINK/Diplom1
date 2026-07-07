from pymongo import MongoClient
import os
from schema import rep

# Берём переменную окружения из compose
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017/")
client = MongoClient(MONGODB_URL)
base = client[rep["name_base"]]

def database_exists(database_name: str):
    database_list = client.list_database_names()
    return database_name in database_list