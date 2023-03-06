
import schedule
import time
from pymongo import MongoClient
import datetime

client = MongoClient("mongodb://mongodb:27017/")
database = client.test_chat_db

def delete_chat():
    messages = database.chat_messages.find({})
    for message in messages:
        chat_message = message["messages"]
        for mes in chat_message:
            time_mes = datetime.strptime(mes["time"], "%d/%m/%Y %H:%M:%S")
            current_time = datetime.now().replace(month=datetime.now().month-6).strftime("%d/%m/%Y %H:%M:%S")
            if current_time > time_mes:
                key = message["key"]
                database.chat_messages.update_one({"key": key}, {"$pull": {"messages": {"time": time_mes}}})

schedule.every().hour.do(delete_chat)

while True:
    schedule.run_pending()
    time.sleep(1)