# author : Swapnil Chadotra , Niketan Chandarana
from flask import (
    Flask,
    session,
    redirect,
    request,
    render_template,
    jsonify,
    send_file,
)
import os
import time
from datetime import date
from flask.helpers import send_from_directory
from pymongo import MongoClient
import requests as req
from user_class import User
from bson import json_util
from werkzeug.utils import secure_filename
from flask_cors import CORS
from random import randint
from flask_socketio import SocketIO, join_room, leave_room, send, emit
from datetime import datetime
import pika
import random
import re
import base64
import string
import shutil

# For file uploading and static files
CURRENT_PATH = os.getcwd()

# Mongo DB working link
client = MongoClient("mongodb://mongodb:27017/")
database = client.test_chat_db

# Different collections of the MonoDB Database
user_collection = database.users
otp_collection = database.otps
user_key_collection = database.user_keys
friend_list_collection = database.friend_lists
chat_key = database.chat_keys
chat_messages = database.chat_messages
# The app variable for running the server
app = Flask(__name__)

# For decalring the session
app.config["SECRET_KEY"] = "tamburkerjfwerf73rt73rfwfnouh"

# For uploading the profile pictures of the user
PROFILE_FOLDER = os.path.join("static", "user_profile")
GROUP_PROFILE = os.path.join("static", "group_profile")
FILE_UPLOADS = os.path.join("static", "file_uploads")
app.config["UPLOAD_PATH"] = PROFILE_FOLDER
app.config["GROUP_PROFILE"] = GROUP_PROFILE
app.config["FILE_UPLOADS"] = FILE_UPLOADS
# For allowing the requests from the AJAX script
CORS(app)

# Socket variable initializing the socket connection
socketio = SocketIO(app, manage_session=True)
ONLINE = []


def check_username(username: str) -> bool:
    """Checks the database that username exists

    Args:
        username (str): Username of the User

    Returns:
        bool: True or False on the basis of database result
    """
    try:
        message_log = {
            "message": "Check Username function is called",
            "type": "info",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )
        user = [
            usernames
            for usernames in user_collection.find({"username": username})
        ]
        if len(user) != 0:
            message_log = {
                "message": "Username : " + username + " exists",
                "type": "info",
            }
            channel.basic_publish(
                exchange="",
                routing_key="user_logs_chat_system",
                body=json_util.dumps(message_log),
            )
            return False
        message_log = {
            "message": "Username : " + username + " does'nt exists",
            "type": "info",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )
        return True
    except Exception as e:
        message_log = {
            "message": "{}".format(e),
            "type": "error",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )
        return False


def send_verification_link(user_email: str, username: str):
    """Send the verification link to the User who just signed up

    Args:
        user_email (str): User's email on whichit has to be sent
        username (str): Username for primary key of the collection OTP
    """
    try:
        # Request to the hashing service which will respond the hashed link
        # The hashed link will be URL friendly
        message_log = {
            "message": "Send verification link is called !!",
            "type": "info",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )
        response_from_api = req.post("http://password_hash:9000/get_link")
        data = {
            "email": user_email,
            "link": "http://0.0.0.0:8080/user_verification/"
            + response_from_api.content.decode("utf-8"),
        }

        # Insertion in the OTP table
        otp_collection.insert_one(
            {
                "otp": response_from_api.content.decode("utf-8"),
                "username": username,
            }
        )

        message_log = {
            "message": "OTP is inserted !!",
            "type": "info",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )

        # Sending the request to the mailer service to mail the link to the
        # user
        req.post(
            "http://mailer:9001/send_link",
            data=json_util.dumps(data),
            headers={"Content-Type": "application/json"},
        )

        message_log = {
            "message": "Verification link sent to the user!!",
            "type": "info",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )

    except Exception as e:
        message_log = {
            "message": "{}".format(e),
            "type": "error",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )
        print("Error")


@app.route("/logout", methods=["GET"])
def log_out():
    """Logs the user out of the server"""
    if "username" in session:

        # pops the username variable from the session variable
        message_log = {
            "message": "Username : "
            + session["username"]
            + " logs out of the system",
            "type": "info",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )
        session.pop("username")
        return redirect("http://0.0.0.0:8080/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Logins the User"""
    if request.method == "GET":
        return render_template("index.html")
    elif request.method == "POST":
        username = request.form["username"]
        user = [
            usernames
            for usernames in user_collection.find({"username": username})
        ]

        # Checks that the user exists and is verified

        if len(user) == 1 and user[0]["verified"]:
            password = request.form["password"]
            db_pass = user[0]["password"]
            json_password = {"password": password, "db": db_pass}

            # Requests the password hash service to check whether the password
            # entered is correct or not

            respone_from_check_password = req.post(
                "http://password_hash:9000/check_password",
                data=json_util.dumps(json_password),
                headers={"Content-Type": "application/json"},
            )

            # decodes the reponse from the hash service

            respone_from_check_password = (
                respone_from_check_password.content.decode("utf-8")
            )
            if respone_from_check_password == "ok":
                message_log = {
                    "message": "Username : "
                    + username
                    + " logs in the system",
                    "type": "info",
                }
                channel.basic_publish(
                    exchange="",
                    routing_key="user_logs_chat_system",
                    body=json_util.dumps(message_log),
                )
                session["username"] = username
                return redirect("http://0.0.0.0:8080/user_home")
        else:
            return redirect("http://0.0.0.0:8080/sign_up")


@app.route("/sign_up", methods=["GET", "POST"])
def sign_up():
    """Decides the type of request
    if GET then renders the sign_up.html page for the user

    if POST then registers the user
    """
    if request.method == "GET":
        return render_template("index.html")
    elif request.method == "POST":
        username = request.form["username"]

        # checking that the user does'nt exist in the system
        if check_username(username):
            name = request.form["name"]
            email = request.form["email"]
            password = request.form["password"]
            confirm_password = request.form["confirm_password"]
            about = request.form["about"]

            # creating a user type object
            user_object = User(
                username, name, email, password, confirm_password
            )

            # user's detail authentication

            if (
                user_object.check_email()
                and user_object.check_password()
                and request.files is not None
            ):
                json_password = {"password": password}
                respone_from_password_hash = req.post(
                    "http://password_hash:9000/create_hash",
                    data=json_util.dumps(json_password),
                    headers={"Content-Type": "application/json"},
                )
                if (
                    respone_from_password_hash.content.decode("utf-8")
                    != "Error"
                ):
                    # Uploading the users profile
                    profile_file = request.files["profile_picture"]
                    filename = secure_filename(profile_file.filename)
                    fileExtension = os.path.splitext(filename)[1]
                    profile_file.save(
                        os.path.join(
                            app.config["UPLOAD_PATH"], username + fileExtension
                        )
                    )

                    # Preparing the Database's Skeleton

                    user_data = {
                        "username": user_object.username,
                        "hashtag": str(randint(100000, 999999)),
                        "name": user_object.name,
                        "email": user_object.email,
                        "password": respone_from_password_hash.content.decode(
                            "utf-8"
                        ),
                        "profile_location": username + fileExtension,
                        "verified": False,
                        "about": about,
                        "notification_key": generate_random_hash(),
                        "theme": "light",
                    }

                    # inerting the data

                    user_collection.insert_one(user_data)
                    friend_list_collection.insert(
                        {"username": username, "friend_list": []}
                    )
                    user_key_collection.insert_one(
                        {"username": username, "key_list": []}
                    )
                    # sending the verification link

                    send_verification_link(user_object.email, username)
                    message_log = {
                        "message": "Username : " + username + " sign ups",
                        "type": "info",
                    }
                    channel.basic_publish(
                        exchange="",
                        routing_key="user_logs_chat_system",
                        body=json_util.dumps(message_log),
                    )
                    return redirect("http://0.0.0.0:8080/login")
        return redirect("http://0.0.0.0:8080/sign_up")
    else:
        return redirect("http://0.0.0.0:8080/")


def generate_random_hash():
    key = "".join(
        random.choice(
            string.ascii_uppercase + string.ascii_lowercase + string.digits
        )
        for _ in range(16)
    )
    return key


@app.route("/user_verification/<verification_link>", methods=["GET"])
def user_verification(verification_link: str):
    """Checks the verification link to the user

    Args:
        verification_link (str): Verification link recieved by the user

    Returns:
        Updates the 'verified' status in the database
    """
    if request.method == "GET":
        otp = [
            otps for otps in otp_collection.find({"otp": verification_link})
        ]
    if len(otp) != 0:
        username = otp[0]["username"]
        user_collection.update_one(
            {"username": username}, {"$set": {"verified": True}}
        )
        otp_collection.delete_one({"username": username})
        message_log = {
            "message": "Username : "
            + username
            + " successfully verfies himself",
            "type": "info",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )
        return redirect("http://0.0.0.0:8080/login")
    else:
        return redirect("http://0.0.0.0:8080/sign_up")


@app.route("/user_check", methods=["POST"])
def user_check():
    """Real Checking that user exists or not"""
    if request.method == "POST":
        username = request.form["username"]

        # Fetching the result from the database

        user = [
            usernames
            for usernames in user_collection.find({"username": username})
        ]
        if len(user) != 0:
            return jsonify("User Exists")
        return jsonify("Userhandle is unique")


@app.route("/user_home", methods=["GET"])
def user_home():
    """Takes the user to his/her homepage

    Returns:
        Renders the homepage interface
    """
    if "username" in session:
        username = session["username"]
        message_log = {
            "message": "Username : "
            + session["username"]
            + " visited the home page",
            "type": "info",
        }
        channel.basic_publish(
            exchange="",
            routing_key="user_logs_chat_system",
            body=json_util.dumps(message_log),
        )

        # Gathering Data such as profile, name from the database

        user = user_collection.find_one({"username": username})
        profile = os.path.join(
            app.config["UPLOAD_PATH"],
            user_collection.find_one({"username": username})[
                "profile_location"
            ],
        )
        number = 0
        try:
            number = len(
                friend_list_collection.find_one({"username": username})[
                    "friend_list"
                ]
            )
        except Exception:
            number = 0
        try:
            groups = (
                len(
                    user_key_collection.find_one({"username": username})[
                        "key_list"
                    ]
                )
                - number
            )
        except Exception:
            groups = 0
        return render_template(
            "user_home.html",
            username=username,
            profile_image=profile,
            about=user["about"],
            hashtag=user["hashtag"],
            number_of_friends=number,
            groups=groups,
        )
    else:
        return redirect("http://0.0.0.0:8080/login")


@app.route("/add_friend", methods=["GET", "POST"])
def add_friends():
    """Adds the friend in the database i.e. MongoDB"""
    if "username" in session:
        if request.method == "GET":
            return render_template("add_friends.html")
        if request.method == "POST":
            try:
                username = session["username"]
                user_friends = friend_list_collection.find_one(
                    {"username": username}
                )
                friend_username = request.form["username"]
                friend_hashtag = request.form["hashtag"]
                friend = user_collection.find_one(
                    {"username": friend_username, "hashtag": friend_hashtag}
                )

                # Some corner case handling

                if friend_username != username:
                    if friend is not None and (
                        not check_friend_exist(friend_username)
                    ):
                        if user_friends["friend_list"] == {}:
                            data = []
                        else:
                            data = user_friends["friend_list"]
                        add_to_friends(
                            username, friend_username, friend["hashtag"], data
                        )
                        if (
                            friend_list_collection.find_one(
                                {"username": friend_username}
                            )["friend_list"]
                            == {}
                        ):
                            data = []
                        else:
                            data = friend_list_collection.find_one(
                                {"username": friend_username}
                            )["friend_list"]
                        add_to_friends(
                            friend_username,
                            username,
                            user_collection.find_one({"username": username})[
                                "hashtag"
                            ],
                            data,
                        )
                        add_key(username, friend_username)
                        message_log = {
                            "message": "Username : "
                            + username
                            + " called the add friend endpoint",
                            "type": "info",
                        }
                        channel.basic_publish(
                            exchange="",
                            routing_key="user_logs_chat_system",
                            body=json_util.dumps(message_log),
                        )
                        return redirect("/user_home")
                    else:
                        return redirect("/add_friend")
                else:
                    return redirect("/add_friend")
            except Exception as e:
                message_log = {
                    "message": "{}".format(e),
                    "type": "error",
                }
                channel.basic_publish(
                    exchange="",
                    routing_key="user_logs_chat_system",
                    body=json_util.dumps(message_log),
                )
                return redirect("/user_home")
    else:
        return redirect("/login")


def add_key(username: str, friend_username: str):
    """Adds the chat key to the database so that two users can text themselves on a
        unique socket

    Args:
        username (str): Username of the user
        friend_username (str): User's friend's username
    """

    # Generating a key

    message_log = {
        "message": "Username : "
        + session["username"]
        + "shared a key on which they can chat/communicate via sockets"
        + friend_username,
        "type": "info",
    }
    channel.basic_publish(
        exchange="",
        routing_key="user_logs_chat_system",
        body=json_util.dumps(message_log),
    )

    key = username + generate_random_hash() + friend_username
    user_key_collection.update_one(
        {"username": username}, {"$push": {"key_list": key}}
    )
    user_key_collection.update_one(
        {"username": friend_username}, {"$push": {"key_list": key}}
    )
    chat_key.insert_one(
        {
            "key": key,
            "type": "personal",
            "users": [username, friend_username],
            "chat-theme": "blue",
            "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        }
    )
    chat_messages.insert_one({"key": key, "messages": []})


def add_to_friends(
    username: str, friend_username: str, hashtag: str, friend_list: list
):
    """Adds the friend to the user's database and vice versa

    Args:
        username (str): Username of the user
        friend_username (str): User's friend username
        hashtag (str): The hashtag associated with the friend of user
        friend_list (list): List of the database
    """
    message_log = {
        "message": "Username : "
        + session["username"]
        + "became friends with "
        + friend_username,
        "type": "info",
    }
    channel.basic_publish(
        exchange="",
        routing_key="user_logs_chat_system",
        body=json_util.dumps(message_log),
    )
    friend_list.append(
        {
            "username": friend_username,
            "hashtag": hashtag,
        }
    )
    friend_list_collection.delete_one({"username": username})
    friend_list_collection.insert_one(
        {"username": username, "friend_list": friend_list}
    )


def check_friend_exist(friend_username: str) -> bool:
    """Checks whether the friend is already the friend of our user

    Args:
        friend_username (str): User's friend's username

    Returns:
        bool: Returns True or False
    """
    if "username" in session:
        username = session["username"]
        try:
            message_log = {
                "message": "Check Friend function has been called",
                "type": "info",
            }
            channel.basic_publish(
                exchange="",
                routing_key="user_logs_chat_system",
                body=json_util.dumps(message_log),
            )
            # Checking te existence of the username

            friend_list = friend_list_collection.find_one(
                {"username": username}
            )["friend_list"]
            for friends in friend_list:
                if friend_username == friends["username"]:
                    return True
            return False
        except Exception as e:
            message_log = {
                "message": "{}".format(e),
                "type": "error",
            }
            channel.basic_publish(
                exchange="",
                routing_key="user_logs_chat_system",
                body=json_util.dumps(message_log),
            )
            return True
    else:
        True


@app.route("/create_group", methods=["GET", "POST"])
def create_group():
    if "username" in session:
        username = session["username"]
        if request.method == "GET":
            friend_list = friend_list_collection.find_one(
                {"username": username}
            )["friend_list"]
            data_to_be_sent = []
            for friends in friend_list:
                friends_name = user_collection.find_one(
                    {"username": friends["username"]}
                )["name"]
                data_to_be_sent.append(
                    {"username": friends["username"], "name": friends_name}
                )
            return render_template(
                "create_group.html", friend_list=data_to_be_sent
            )
        if request.method == "POST":
            group_name = request.form["group_name"]
            list_of_friends = request.form.getlist("arr[]")
            list_of_admins = request.form.getlist("brr[]")
            set_of_friends = set(list_of_friends)
            admin_set = set(list_of_admins)
            username = session["username"]
            friend_list = friend_list_collection.find_one(
                {"username": username}
            )["friend_list"]
            accepted = []
            accepted.append({"username": username, "isAdmin": True})
            my_group_id = generate_random_hash()
            user_key_collection.update_one(
                {"username": username},
                {"$push": {"key_list": my_group_id}},
            )
            for friends in friend_list:
                if friends["username"] in set_of_friends:
                    user_key_collection.update_one(
                        {"username": friends["username"]},
                        {"$push": {"key_list": my_group_id}},
                    )
                    if friends["username"] in admin_set:
                        accepted.append(
                            {"username": friends["username"], "isAdmin": True}
                        )
                    else:
                        accepted.append(
                            {"username": friends["username"], "isAdmin": False}
                        )
            profile_file = request.files["group_profile"]
            filename = secure_filename(profile_file.filename)
            fileExtension = os.path.splitext(filename)[1]
            profile_file.save(
                os.path.join(
                    app.config["GROUP_PROFILE"], my_group_id + fileExtension
                )
            )
            chat_key.insert_one(
                {
                    "key": my_group_id,
                    "type": "group",
                    "users": accepted,
                    "group_name": group_name,
                    "group_description": request.form["group_description"],
                    "group_profile": my_group_id + fileExtension,
                    "created_by": username,
                    "chat-theme": "blue",
                    "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                }
            )
            chat_messages.insert_one({"key": my_group_id, "messages": []})
            return redirect("/user_home")
    else:
        return redirect("/login")


@app.route("/group-settings/<key>", methods=["GET", "POST"])
def group_settings(key):
    if "username" in session:
        username = session["username"]
        if request.method == "GET":
            id_ = {"id": key}
            hash_id = req.post(
                "http://password_hash:9000/get_decrypted_hash",
                data=json_util.dumps(id_),
                headers={"Content-Type": "application/json"},
            )
            hash_id = hash_id.content.decode("utf-8")
            friend_list = friend_list_collection.find_one(
                {"username": username}
            )["friend_list"]
            data_to_be_sent = []
            for friends in friend_list:
                friends_name = user_collection.find_one(
                    {"username": friends["username"]}
                )["name"]
                data_to_be_sent.append(
                    {"username": friends["username"], "name": friends_name}
                )
            group_members = chat_key.find_one({"key": hash_id})["users"]
            non_admin = []
            admin = []
            isUserAdmin = False
            for members in group_members:
                if members["username"] == username:
                    if members["isAdmin"] is True:
                        isUserAdmin = True
                    continue
                elif members["isAdmin"] is True:
                    admin.append(
                        {
                            "name": user_collection.find_one(
                                {"username": members["username"]}
                            )["name"],
                            "username": members["username"],
                        }
                    )
                non_admin.append(
                    {
                        "name": user_collection.find_one(
                            {"username": members["username"]}
                        )["name"],
                        "username": members["username"],
                    }
                )
            final_list = []
            for users in data_to_be_sent:
                if users not in non_admin and users not in admin:
                    final_list.append(users)
            admin_list = []
            for users in data_to_be_sent:
                if users not in non_admin and users not in admin:
                    admin_list.append(users)
                if users in non_admin and users not in admin:
                    admin_list.append(users)
            group_name = chat_key.find_one({"key": hash_id})["group_name"]
            group_description = chat_key.find_one({"key": hash_id})[
                "group_description"
            ]
            return render_template(
                "group_settings.html",
                username=username,
                admin_to_add=admin_list,
                friend_list=final_list,
                non_admin=non_admin,
                admin=admin,
                isUserAdmin=isUserAdmin,
                group_name=group_name,
                group_description=group_description,
                key=key,
            )
        if request.method == "POST":
            id_ = {"id": key}
            hash_id = req.post(
                "http://password_hash:9000/get_decrypted_hash",
                data=json_util.dumps(id_),
                headers={"Content-Type": "application/json"},
            )
            hash_id = hash_id.content.decode("utf-8")
            group_name = request.form["group_name"]
            group_description = request.form["group_description"]
            profile_file = request.files["group_profile"]
            if profile_file.filename != "":
                group_profile_loc = chat_key.find_one({"key": hash_id})[
                    "group_profile"
                ]
                os.remove(
                    os.path.join(
                        app.config["GROUP_PROFILE"],
                        group_profile_loc,
                    )
                )
                filename = secure_filename(profile_file.filename)
                fileExtension = os.path.splitext(filename)[1]
                profile_file.save(
                    os.path.join(
                        app.config["GROUP_PROFILE"],
                        hash_id + fileExtension,
                    )
                )
                chat_key.update_one(
                    {"key": hash_id},
                    {
                        "$set": {"group_profile": hash_id + fileExtension},
                    },
                )
            chat_key.update_one(
                {"key": hash_id},
                {
                    "$set": {
                        "group_name": group_name,
                        "group_description": group_description,
                    },
                },
            )
            list_of_new_friends = request.form.getlist("arr[]")
            list_of_new_admins = request.form.getlist("brr[]")
            list_of_remove_friends = request.form.getlist("crr[]")
            list_of_remove_admins = request.form.getlist("drr[]")
            set_of_friends = set(list_of_new_friends)
            admin_set = set(list_of_new_admins)
            remove_friends = set(list_of_remove_friends)
            remove_admins = set(list_of_remove_admins)
            friend_list = friend_list_collection.find_one(
                {"username": username}
            )["friend_list"]
            accepted = []
            for friends in friend_list:
                if friends["username"] in set_of_friends:
                    user_key_collection.update_one(
                        {"username": friends["username"]},
                        {"$push": {"key_list": hash_id}},
                    )
                    if friends["username"] in admin_set:
                        accepted.append(
                            {"username": friends["username"], "isAdmin": True}
                        )
                    else:
                        accepted.append(
                            {"username": friends["username"], "isAdmin": False}
                        )
            if accepted != []:
                for accept in accepted:
                    chat_key.update_one(
                        {"key": hash_id},
                        {"$push": {"users": accept}},
                    )
            for user in remove_friends:
                user_key_collection.update_one(
                    {"username": user}, {"$pull": {"key_list": hash_id}}
                )
                chat_key.update_one(
                    {"key": hash_id}, {"$pull": {"users": {"username": user}}}
                )
            for user in remove_admins:
                chat_key.update_one(
                    {"key": hash_id, "users.username": user},
                    {"$set": {"users.$.isAdmin": False}},
                )
            return redirect("/message")


@app.route("/message", methods=["GET"])
def chat_page():
    global ONLINE
    if "username" in session:
        username = session["username"]
        user_keys = user_key_collection.find_one({"username": username})[
            "key_list"
        ]
        user_chat_mode = user_collection.find_one({"username": username})[
            "theme"
        ]
        user_profile = user_collection.find_one({"username": username})[
            "profile_location"
        ]
        user_notification_key = user_collection.find_one(
            {"username": username}
        )["notification_key"]
        chat_list_data = []
        for keys in user_keys:
            data = {}
            id_ = {"id": keys}
            hash_id = req.post(
                "http://password_hash:9000/get_id_hash",
                data=json_util.dumps(id_),
                headers={"Content-Type": "application/json"},
            )
            hash_id = hash_id.content.decode("utf-8")
            key_data = chat_key.find_one({"key": keys})
            if key_data["type"] == "group":
                group_name = key_data["group_name"]
                group_profile = key_data["group_profile"]
                message_count = chat_messages.aggregate(
                    [
                        {"$match": {"key": keys}},
                        {
                            "$project": {
                                "item": 1,
                                "count": {"$size": "$messages"},
                            }
                        },
                    ]
                )
                message_count = list(message_count)
                message_count = message_count[0]["count"]
                last_message = ""
                time_at = ""
                if message_count == 0:
                    last_message = "Group created on " + key_data["time"]
                    time_at = key_data["time"]
                else:
                    last_message = chat_messages.aggregate(
                        [
                            {"$match": {"key": keys}},
                            {
                                "$project": {
                                    "item": 1,
                                    "last_message": {
                                        "$slice": ["$messages", 1]
                                    },
                                }
                            },
                        ]
                    )
                    last_message = list(last_message)
                    if last_message[0]["last_message"][0]["type"] == "image":
                        if (
                            last_message[0]["last_message"][0][
                                "sender_username"
                            ]
                            == username
                        ):
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = "You sent an Image"
                        else:
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = "Sent an Image"
                    elif last_message[0]["last_message"][0]["type"] == "file":
                        if (
                            last_message[0]["last_message"][0][
                                "sender_username"
                            ]
                            == username
                        ):
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = "You sent an Attachment"
                        else:
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = "Sent an Attachment"
                    elif last_message[0]["last_message"][0]["type"] == "text":
                        if (
                            last_message[0]["last_message"][0][
                                "sender_username"
                            ]
                            == username
                        ):
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = (
                                "You : "
                                + last_message[0]["last_message"][0]["message"]
                            )
                        else:
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = last_message[0]["last_message"][0][
                                "message"
                            ]
                data = {
                    "type": "group",
                    "key": hash_id,
                    "group_name": group_name,
                    "group_profile": os.path.join(
                        app.config["GROUP_PROFILE"], group_profile
                    ),
                    "last_message": last_message,
                    "time": time_at,
                    "unhashed": keys,
                }
            else:
                friend_username = [
                    user for user in key_data["users"] if user != username
                ]
                friend_username = friend_username[0]
                friend_profile = user_collection.find_one(
                    {"username": friend_username}
                )["profile_location"]
                message_count = chat_messages.aggregate(
                    [
                        {"$match": {"key": keys}},
                        {
                            "$project": {
                                "item": 1,
                                "count": {"$size": "$messages"},
                            }
                        },
                    ]
                )
                message_count = list(message_count)
                message_count = message_count[0]["count"]
                last_message = ""
                time_at = ""
                if message_count == 0:
                    last_message = "Friends since " + key_data["time"]
                    time_at = key_data["time"]
                else:
                    last_message = chat_messages.aggregate(
                        [
                            {"$match": {"key": keys}},
                            {
                                "$project": {
                                    "item": 1,
                                    "last_message": {
                                        "$slice": ["$messages", 1]
                                    },
                                }
                            },
                        ]
                    )
                    last_message = list(last_message)
                    if last_message[0]["last_message"][0]["type"] == "image":
                        if (
                            last_message[0]["last_message"][0][
                                "sender_username"
                            ]
                            == username
                        ):
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = "You sent an Image"
                        else:
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = "Sent an Image"
                    elif last_message[0]["last_message"][0]["type"] == "file":
                        if (
                            last_message[0]["last_message"][0][
                                "sender_username"
                            ]
                            == username
                        ):
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = "You sent an Attachment"
                        else:
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = "Sent an Attachment"
                    elif last_message[0]["last_message"][0]["type"] == "text":
                        if (
                            last_message[0]["last_message"][0][
                                "sender_username"
                            ]
                            == username
                        ):
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = (
                                "You : "
                                + last_message[0]["last_message"][0]["message"]
                            )
                        else:
                            time_at = last_message[0]["last_message"][0][
                                "time"
                            ]
                            last_message = last_message[0]["last_message"][0][
                                "message"
                            ]
                data = {
                    "type": "personal",
                    "key": hash_id,
                    "friend_username": friend_username,
                    "profile": os.path.join(
                        app.config["UPLOAD_PATH"], friend_profile
                    ),
                    "last_message": last_message,
                    "time": time_at,
                    "unhashed": keys,
                    "isOnline": friend_username in ONLINE,
                }
            chat_list_data.append(data)
        result = sorted(
            chat_list_data,
            key=lambda x: datetime.strptime(x["time"], "%d/%m/%Y %H:%M:%S"),
            reverse=True,
        )
        return render_template(
            "temp_chat.html",
            username=username,
            mode=user_chat_mode,
            user_profile=os.path.join(app.config["UPLOAD_PATH"], user_profile),
            chat_list=result,
            notification_key=user_notification_key,
        )


@socketio.on("join")
def on_join(data):
    """User starts a chat with a desired person"""
    id_ = {"id": data["key"]}
    hash_id = req.post(
        "http://password_hash:9000/get_decrypted_hash",
        data=json_util.dumps(id_),
        headers={"Content-Type": "application/json"},
    )
    hash_id = hash_id.content.decode("utf-8")
    join_room(hash_id)


@socketio.on("new_message")
def on_message(data):
    """User starts a chat with a desired person"""
    id_ = {"id": data["key"]}
    hash_id = req.post(
        "http://password_hash:9000/get_decrypted_hash",
        data=json_util.dumps(id_),
        headers={"Content-Type": "application/json"},
    )
    hash_id = hash_id.content.decode("utf-8")
    message = {}
    if data["type"] == "text":
        message = {
            "user_type": data["user_type"],
            "sender_username": data["sender_username"],
            "sender_profile": data["sender_profile"],
            "message": data["message"],
            "type": data["type"],
            "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "key": hash_id,
        }
        channel.basic_publish(
            exchange="",
            routing_key="message_queue",
            body=json_util.dumps(message),
        )
        emit("message", message, room=hash_id)
    elif data["type"] == "image":
        base64_data = re.sub("^data:image/.+;base64,", "", data["message"])
        data["message"] = base64_data
        generated_name = generate_random_hash()
        data["generated_name"] = generated_name
        ext = data["file_name"].split(".")
        data["saved_at"] = (
            hash_id + "\\images\\" + generated_name + "." + ext[1]
        )
        data["key"] = hash_id
        data["time"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        channel.basic_publish(
            exchange="",
            routing_key="message_queue",
            body=json_util.dumps(data),
        )
        time.sleep(2)
        emit("message", data, room=hash_id)
    elif data["type"] == "file":
        base64_data = data["message"].split(",")[1:2]
        data["message"] = base64_data[0]
        generated_name = generate_random_hash()
        data["generated_name"] = generated_name
        ext = data["file_name"].split(".")
        data["key"] = hash_id
        data["time"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        channel.basic_publish(
            exchange="",
            routing_key="message_queue",
            body=json_util.dumps(data),
        )
        data["link"] = hash_id + "/" + generated_name + "." + ext[1]
        emit("message", data, room=hash_id)
    notification_message = {}
    if data["type"] == "text":
        notification_message = {
            "message": data["message"],
            "sender": data["sender_username"],
        }
    if data["type"] == "image":
        notification_message = {
            "message": "shared an Image",
            "sender": data["sender_username"],
        }
    if data["type"] == "file":
        notification_message = {
            "message": "shared an Attachment",
            "sender": data["sender_username"],
        }
    list_of_users = chat_key.find_one({"key": hash_id})["users"]
    temp_list = []
    if data["user_type"] == "group":
        for u in list_of_users:
            temp_list.append(u["username"])
        list_of_users = temp_list
    for user in list_of_users:
        get_noti_key = user_collection.find_one({"username": user})[
            "notification_key"
        ]
        noti_data = data
        if user == notification_message["sender"]:
            noti_data = {
                "notification": "You : " + notification_message["message"],
                "key": hash_id,
            }
        else:
            noti_data = {
                "notification": notification_message["sender"]
                + " "
                + notification_message["message"],
                "key": hash_id,
            }
        emit("notification", noti_data, room=get_noti_key)


@socketio.on("join_notification")
def join_notification(data):
    global ONLINE
    if data["username"] not in ONLINE:
        ONLINE.append(data["username"])
    join_room(data["key"])


@socketio.on("typing")
def on_typing(data):
    id_ = {"id": data["key"]}
    hash_id = req.post(
        "http://password_hash:9000/get_decrypted_hash",
        data=json_util.dumps(id_),
        headers={"Content-Type": "application/json"},
    )
    hash_id = hash_id.content.decode("utf-8")
    emit("typing", data, room=hash_id)


@socketio.on("nottyping")
def on_not_typing(data):
    id_ = {"id": data["key"]}
    hash_id = req.post(
        "http://password_hash:9000/get_decrypted_hash",
        data=json_util.dumps(id_),
        headers={"Content-Type": "application/json"},
    )
    hash_id = hash_id.content.decode("utf-8")
    emit("nottyping", data, room=hash_id)


@socketio.on("leave")
def on_leave(data):
    """User starts a chat with a desired person"""
    id_ = {"id": data["key"]}
    hash_id = req.post(
        "http://password_hash:9000/get_decrypted_hash",
        data=json_util.dumps(id_),
        headers={"Content-Type": "application/json"},
    )
    hash_id = hash_id.content.decode("utf-8")
    leave_room(hash_id)


@app.route("/load_messages", methods=["POST"])
def load_message():
    if request.method == "POST":
        details = request.get_json()
        key = details["key"]
        id_ = {"id": key}
        hash_id = req.post(
            "http://password_hash:9000/get_decrypted_hash",
            data=json_util.dumps(id_),
            headers={"Content-Type": "application/json"},
        )
        hash_id = hash_id.content.decode("utf-8")
        from_ = details["from"]
        to_ = details["to"]
        size = chat_messages.aggregate(
            [
                {"$match": {"key": hash_id}},
                {
                    "$project": {
                        "item": 1,
                        "count": {"$size": "$messages"},
                    }
                },
            ]
        )
        size = list(size)
        size = size[0]["count"]
        if from_ >= size:
            return {"msg": json_util.dumps("no")}
        if to_ > size:
            to_ = size
        messages = chat_messages.aggregate(
            [
                {"$match": {"key": hash_id}},
                {
                    "$project": {
                        "item": 1,
                        "message": {
                            "$slice": ["$messages", from_, to_ - from_]
                        },
                    }
                },
            ]
        )
        data_to_be_sent = []
        messages = list(messages)[0]["message"]
        for message in messages:
            message.pop("key")
            data_to_be_sent.append(message)
        return {"msg": json_util.dumps(data_to_be_sent)}


@app.route("/files/<key>/<file_name>")
def download_target(key, file_name):
    if "username" in session:
        path = os.path.join(os.getcwd(),FILE_UPLOADS, key + "/documents/" + file_name)
        return send_file(path, as_attachment=True)


@app.route("/get_details", methods=["POST"])
def get_details():
    if request.method == "POST":
        details = request.get_json()
        key = details["key"]
        id_ = {"id": key}
        hash_id = req.post(
            "http://password_hash:9000/get_decrypted_hash",
            data=json_util.dumps(id_),
            headers={"Content-Type": "application/json"},
        )
        hash_id = hash_id.content.decode("utf-8")
        chat_details = chat_key.find_one({"key": hash_id})
        data_to_be_sent = []
        for user in chat_details["users"]:
            if chat_details["type"] == "group":
                user_data = {
                    "username": user["username"],
                    "profile": "static\\user_profile\\"
                    + user_collection.find_one({"username": user["username"]})[
                        "profile_location"
                    ],
                    "group_description": chat_key.find_one({"key": hash_id})[
                        "group_description"
                    ],
                }
            else:
                user_data = {
                    "username": user,
                    "profile": "static\\user_profile\\"
                    + user_collection.find_one({"username": user})[
                        "profile_location"
                    ],
                }
            data_to_be_sent.append(user_data)
        chat_details["users"] = data_to_be_sent
        return {"details": json_util.dumps(chat_details)}


@app.route("/leave-group/<key>", methods=["GET"])
def leave_group(key):
    if "username" in session:
        if request.method == "GET":
            username = session["username"]
            key = key
            id_ = {"id": key}
            hash_id = req.post(
                "http://password_hash:9000/get_decrypted_hash",
                data=json_util.dumps(id_),
                headers={"Content-Type": "application/json"},
            )
            hash_id = hash_id.content.decode("utf-8")
            isAdmin = chat_key.find_one(
                {"key": hash_id},
                {"users": {"$elemMatch": {"username": username}}},
            )["users"][0]["isAdmin"]
            chat_key.update_one(
                {"key": hash_id}, {"$pull": {"users": {"username": username}}}
            )
            user_key_collection.update_one(
                {"username": username}, {"$pull": {"key_list": hash_id}}
            )
            if isAdmin:
                new_admin = chat_key.aggregate(
                    [
                        {"$match": {"key": hash_id}},
                        {"$unwind": "$users"},
                        {"$sample": {"size": 1}},
                    ]
                )
                new_admin = list(new_admin)[0]["users"]["username"]
                chat_key.update_one(
                    {
                        "key": hash_id,
                        "users": {"$elemMatch": {"username": new_admin}},
                    },
                    {
                        "$set": {
                            "users.$.isAdmin": True,
                        }
                    },
                )
            return redirect("/user_home")


@app.route("/delete-group/<key>", methods=["GET"])
def delete_group(key):
    if "username" in session:
        if request.method == "GET":
            key = key
            id_ = {"id": key}
            hash_id = req.post(
                "http://password_hash:9000/get_decrypted_hash",
                data=json_util.dumps(id_),
                headers={"Content-Type": "application/json"},
            )
            hash_id = hash_id.content.decode("utf-8")
            os.remove(
                os.path.join(
                    app.config["GROUP_PROFILE"],
                    chat_key.find_one({"key": hash_id})["group_profile"],
                )
            )
            shutil.rmtree(
                os.path.join(
                    app.config["FILE_UPLOADS"],
                    hash_id,
                )
            )
            list_of_users = chat_key.find_one({"key": hash_id})["users"]
            chat_key.delete_one({"key": hash_id})
            chat_messages.delete_one({"key": hash_id})
            for friends in list_of_users:
                username = friends["username"]
                user_key_collection.update_one(
                    {"username": username}, {"$pull": {"key_list": hash_id}}
                )
            return redirect("/user_home")

@app.route("/change_theme_message", methods=["POST","GET"])
def change_theme_message():
    if request.method == "POST":
        details = request.get_json()
        key = details["key"]
        id_ = {"id": key}
        theme = details["theme"]
        hash_id = req.post(
                "http://password_hash:9000/get_decrypted_hash",
                data=json_util.dumps(id_),
                headers={"Content-Type": "application/json"},
            )
        hash_id = hash_id.content.decode("utf-8")
        #chat_key.update_one({"key":hash_id},{"$set": {"chat-theme":theme}})"""
        return {"ok": json_util.dumps(key)}

@app.route("/change_theme", methods=["POST","GET"])
def change_theme():
    if request.method == "POST":
        details = request.get_json()
        username = details["username"]
        mode = details["mode"]
        user_collection.update_one({"username":username},{"$set": {"theme":mode}})
        return {"ok": json_util.dumps("ok")}

if __name__ == "__main__":
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host="rabbitmq",blocked_connection_timeout=5000)
    )
    channel = connection.channel()
    channel.queue_declare(queue="message_queue")
    message_log = {
        "message": "System Started",
        "type": "info",
    }
    channel.basic_publish(
        exchange="",
        routing_key="user_logs_chat_system",
        body=json_util.dumps(message_log),
    )
    HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
    try:
        PORT = int(os.environ.get("SERVER_HOST", "8080"))
    except ValueError:
        PORT = 8080
    socketio.run(app, HOST, PORT, debug=True)
