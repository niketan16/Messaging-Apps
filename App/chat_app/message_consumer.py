import time
import threading
import pika
import json
from pymongo import MongoClient
import os
import base64
import random
import string

QUEUE_NAME = "message_queue"
THREADS = 5

client = MongoClient("mongodb://mongodb:27017")
database = client.test_chat_db
chat_messages = database.chat_messages
PATH = os.getcwd()


def generate_random_hash():
    key = "".join(
        random.choice(
            string.ascii_uppercase + string.ascii_lowercase + string.digits
        )
        for _ in range(16)
    )
    return key


class ThreadedConsumer(threading.Thread):
    def callback(self, channel, method, properties, body):
        global PATH
        try:
            message = json.loads(body)
            time.sleep(1)
            if message["type"] == "text":
                message_data = {
                    "user_type": message["user_type"],
                    "sender_username": message["sender_username"],
                    "sender_profile": message["sender_profile"],
                    "message": message["message"],
                    "type": message["type"],
                    "time": message["time"],
                    "key": message["key"],
                }
                temp = []
                temp.append(message_data)
                chat_messages.update_one(
                    {"key": message["key"]},
                    {"$push": {"messages": {"$each": temp, "$position": 0}}},
                )
            if message["type"] == "image":
                key = message["key"]
                target = os.path.join(PATH, "static/file_uploads/" + key)
                if not os.path.isdir(target):
                    os.makedirs(target)
                    os.makedirs(target + "/images")
                    os.makedirs(target + "/documents")
                imgdata = base64.b64decode(message["message"])
                ext = message["file_name"].split(".")
                generated_name = message["generated_name"]
                filename = target + "/images/" + generated_name + "." + ext[1]
                with open(filename, "wb") as f:
                    f.write(imgdata)
                message_data = {
                    "user_type": message["user_type"],
                    "sender_username": message["sender_username"],
                    "sender_profile": message["sender_profile"],
                    "saved_at": key
                    + "\\images\\"
                    + generated_name
                    + "."
                    + ext[1],
                    "type": message["type"],
                    "time": message["time"],
                    "file_name": message["file_name"],
                    "key": message["key"],
                }
                temp = []
                temp.append(message_data)
                chat_messages.update_one(
                    {"key": message["key"]},
                    {"$push": {"messages": {"$each": temp, "$position": 0}}},
                )
            if message["type"] == "file":
                key = message["key"]
                target = os.path.join(PATH, "static/file_uploads/" + key)
                if not os.path.isdir(target):
                    os.makedirs(target)
                    os.makedirs(target + "/images")
                    os.makedirs(target + "/documents")
                filedata = base64.b64decode(message["message"])
                ext = message["file_name"].split(".")
                generated_name = message["generated_name"]
                filename = (
                    target + "/documents/" + generated_name + "." + ext[1]
                )
                with open(filename, "wb") as f:
                    f.write(filedata)
                message_data = {
                    "user_type": message["user_type"],
                    "sender_username": message["sender_username"],
                    "sender_profile": message["sender_profile"],
                    "saved_at": key
                    + "\\documents\\"
                    + generated_name
                    + "."
                    + ext[1],
                    "type": message["type"],
                    "time": message["time"],
                    "key": message["key"],
                    "file_name": message["file_name"],
                    "link": key + "/" + generated_name + "." + ext[1],
                }
                temp = []
                temp.append(message_data)
                chat_messages.update_one(
                    {"key": message["key"]},
                    {"$push": {"messages": {"$each": temp, "$position": 0}}},
                )
            channel.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            print(e)

    def __init__(self):
        threading.Thread.__init__(self)
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(host="rabbitmq", blocked_connection_timeout=5000)
        )
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue="message_queue")
        self.channel.basic_qos(prefetch_count=THREADS)
        threading.Thread(
            target=self.channel.basic_consume(
                QUEUE_NAME, on_message_callback=self.callback
            )
        )

    def run(self):
        self.channel.start_consuming()


def main():
    for _ in range(5):
        td = ThreadedConsumer()
        td.start()


if __name__ == "__main__":
    main()
