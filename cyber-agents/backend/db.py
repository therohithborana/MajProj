import os

from dotenv import load_dotenv
from pymongo import ASCENDING, MongoClient


load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "cyberagent")

_client = MongoClient(MONGO_URI)
db = _client[MONGO_DB_NAME]


def init_db():
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.users.create_index([("session_token", ASCENDING)], sparse=True)
    db.websites.create_index([("user_id", ASCENDING), ("created_at", ASCENDING)])
    db.websites.create_index([("user_id", ASCENDING), ("name", ASCENDING)])
    db.incidents.create_index([("website_id", ASCENDING), ("created_at", ASCENDING)])
    db.incidents.create_index([("attack_id", ASCENDING)], unique=True)
