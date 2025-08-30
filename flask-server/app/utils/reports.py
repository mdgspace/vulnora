from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Setup MongoDB client
load_dotenv()
client = MongoClient(os.getenv("MONGODB_URI"))  
db = client[os.getenv("DATABASE_NAME")]
reports_collection = db["reports"]

def save_report(report_doc):
    try:
        report_doc["created_at"] = datetime.utcnow()
        result = reports_collection.insert_one(report_doc)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error saving report: {e}")
        return None

