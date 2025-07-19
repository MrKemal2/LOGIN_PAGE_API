import pymongo.errors
from pymongo import MongoClient

try:
    client = MongoClient("mongodb://localhost:27017/")
    db = client.denemeFaceSecure
    collection = db.user_collection
except pymongo.errors.ConnectionFailure:
    print("MongoDB sunucusuna bağlanılamadı")

def get_user(username):
    if (user := collection.find_one({"username": username})):
        return user
    return None

def get_admin():
    admin_user = collection.find_one({"is_admin": True})
    return admin_user is not None

def add_user(username, full_name, hashed_password, is_admin=False):
    collection.insert_one({
        "username": username,
        "full_name": full_name,
        "hashed_password": hashed_password,
        "is_admin": is_admin
    })

def get_all_users():
    return collection.find()

def delete_user(username):
    result  = collection.delete_one({"username": username})

    if result.deleted_count > 0 :
        return {"status": "success"}
    else:
        return {"status": "error", "message": "Kullanıcı bulunamadı"}
