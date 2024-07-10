import traceback
import os
from uuid import uuid4
from datetime import timedelta

from cs50 import SQL
from flask import Flask, request, json, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

# Configure application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET')
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.json.sort_keys = False
jwt = JWTManager(app)

# Configure CS50 Library to use SQLite database
db = SQL(os.environ.get('DATABASE_URI'))

@app.route("/")
def index():
    return "Welcome to flask"

@app.route("/auth/register", methods=["POST"])
def _register():
    return redirect(url_for('register'))

@app.route("/api/auth/register", methods=["POST"])
def register():
    if request.is_json:
        data = request.json
    else:
        data = json.loads(request.data)

    errors = []

    if not "firstName" in data or not data['firstName']:
        errors.append("firstName")

    if not "lastName" in data or not data['lastName']:
        errors.append("lastName")

    if not "email" in data or not data['email']:
        errors.append("email")

    if not "password" in data or not data['password']:
        errors.append("password")

    if errors:
        response = {
            "errors": [
                {
                    "field": field,
                    "message": f"You must provide {field}"
                }
                for field in errors
            ]
        }
        
        return response, 422
    
    try:
        userid = str(uuid4())
        if not 'phone' in data:
            data['phone'] = None
        db.execute(
            "INSERT INTO users (userid, firstname, lastname, email, password, phone) VALUES(?, ?, ?, ?, ?, ?)",
            userid,
            data["firstName"],
            data["lastName"],
            data["email"],
            generate_password_hash(data["password"]),
            data["phone"]
        )

        orgid = str(uuid4())
        db.execute(
            "INSERT INTO organisations (orgid, name) VALUES(?, ?)",
            orgid,
            data["firstName"] + "'s Organisation"
        )

        record = db.execute(
            "INSERT INTO records (user_id, org_id) VALUES(?, ?)",
            userid, orgid
        )

        access_token = create_access_token(identity=userid, expires_delta=timedelta(minutes=5))

        response = {
            "status": "success",
            "message": "Registration successful",
            "data": {
                "accessToken": access_token,
                "user": {
                    "userId": userid,
                    "firstName": data["firstName"],
                    "lastName": data["lastName"],
                    "email": data["email"],
                    "phone":  data["phone"],
                }
            }
        }

        return response, 201
    except Exception:
        response = {
            "status": "Bad request",
            "message": "Registration unsuccessful",
            "statusCode": 400
        }

        print(traceback.format_exc())

        return response, 400

@app.route("/auth/login", methods=["POST"])
def _login():
    return redirect(url_for('login'))

@app.route("/api/auth/login", methods=["POST"])
def login():
    if request.is_json:
        data = request.json
    else:
        data = json.loads(request.data)

    errors = []

    if not "email" in data or not data['email']:
        errors.append("email")

    if not "password" in data or not data['password']:
        errors.append("password")

    if errors:
        response = {
            "errors": [
                {
                    "field": field,
                    "message": f"You must provide {field}"
                }
                for field in errors
            ]
        }
        
        return response, 422
    
    rows = db.execute("SELECT * FROM users WHERE email = ?", data["email"])

    # Ensure username exists and password is correct
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], data["password"]):
        response = {
            "status": "Bad request",
            "message": "Authentication failed",
            "statusCode": 401
        }

        return response, 401
    access_token = create_access_token(identity=rows[0]["userid"], expires_delta=timedelta(minutes=5))
    response = {
        "status": "success",
        "message": "Login successful",
        "data": {
            "accessToken": access_token,
            "user": {
                "userId": rows[0]["userid"],
                "firstName": rows[0]["firstname"],
                "lastName": rows[0]["lastname"],
                "email": rows[0]["email"],
                "phone": rows[0]["phone"]
            }
        }
    }

    return response, 200

@app.route("/api/api/users/<id>")
@jwt_required()
def get_user(id):
    user_id = get_jwt_identity()
    rows = db.execute("SELECT org_id FROM records WHERE user_id = ?", user_id);
    if len(rows) > 1:
        rows = db.execute("SELECT user_id FROM records WHERE org_id IN (?)", [x['org_id'] for x in rows])
    else:
        rows = db.execute("SELECT user_id FROM records WHERE org_id = ?", [x['org_id'] for x in rows])

    if [x['user_id'] for x in rows if x['user_id'] == id]:
        rows = db.execute("SELECT * FROM users WHERE userid = ?", id)
        print(rows, 4)
        response = {
            "status": "success",
            "message": "<message>",
            "data": {
                "userId": rows[0]["userid"],
                "firstName": rows[0]["firstname"],
                "lastName": rows[0]["lastname"],
                "email": rows[0]["email"],
                "phone": rows[0]["phone"],
            }
        }
        code = 200
    else:
        response = {
            "msg": "You do not have Authorisation"
        }
        code = 401
    
    return response, code

@app.route("/api/api/organisations", methods=["GET", "POST"])
@jwt_required()
def get_organisations():
    user_id = get_jwt_identity()
    if request.method == "GET":
        try:
            rows = db.execute("SELECT org_id FROM records WHERE user_id = ?", user_id)
            if len(rows) > 1:
                rows = db.execute("SELECT * FROM organisations WHERE orgid IN (?)",
                                  [x['org_id'] for x in rows])
            else:
                rows = db.execute("SELECT * FROM organisations WHERE orgid = ?",
                                  rows[0]['org_id'])
            response = {
                "status": "success",
                "message": "<message>",
                "data": {
                    "organisations": [
                        {
                            "orgId": x['orgid'],
                            "name": x['name'],
                            "description": x['description'],
                        }
                        for x in rows
                    ]
                }
            }
            code = 200
        except Exception:
            response = {
                "message": "Could not retrieve organisations"
            }
            code = 400
            print(traceback.format_exc())
        return response, code
    else:
        if request.is_json:
            data = request.json
        else:
            data = json.loads(request.data)

        if not "name" in data or not data['name']:
            response = {
                "errors": [
                    {
                        "field": "name",
                        "message": "You must provide name"
                    }
                ]
            }
            
            return response, 422
        try:
            org_id = str(uuid4())
            rows = db.execute("INSERT INTO organisations (orgid, name, description) VALUES (?, ?, ?)",
                              org_id, data['name'], data['description'])
            print("yes")
            rows = db.execute("INSERT INTO records (user_id, org_id) VALUES (?, ?)",
                              user_id, org_id)
            rows = db.execute("SELECT * FROM organisations WHERE orgid = ?", org_id)
            response = {
                "status": "success",
                "message": "Organisation created successfully",
                "data": {
                    "orgId": rows[0]['orgid'], 
                    "name": rows[0]['name'], 
                    "description": rows[0]['description']
                }
            }
            code = 201
        except:
            response = {
                "status": "Bad Request",
                "message": "Client error",
                "statusCode": 400
            }
            code = 400

        return response, code

@app.route("/api/api/organisations/<orgId>")
@jwt_required()
def get_organisation(orgId):
    user_id = get_jwt_identity()
    rows = db.execute("SELECT org_id from records WHERE user_id = ?", user_id)
    org = [row['org_id'] for row in rows if row['org_id'] == orgId]
    if org:
        rows = db.execute("SELECT * FROM organisations WHERE orgid = ?", orgId)
        response = {
            "status": "success",
            "message": "<message>",
            "data": {
                "orgId": rows[0]['orgid'],
                "name": rows[0]['name'],
                "description": rows[0]['description'],
            }
        }
        return response, 200
    else:
        response = {
            "status": "Bad request",
            "message": "Permission Denied",
            "statusCode": 401
        }

        return response, 401
       

@app.route("/api/api/organisations/<orgId>/users", methods=["POST"])
@jwt_required()
def add_organisation_user(orgId):
    if request.is_json:
        data = request.json
    else:
        data = json.loads(request.data)

    if "userId" not in data or not data['userId']:
        response = {
                "errors": [
                    {
                        "field": "userId",
                        "message": "You must provide userId"
                    }
                ]
            }
            
        return response, 422
    try:
        rows = db.execute("SELECT userid FROM users WHERE userid = ?",
        
                        data['userId'])
        rows = db.execute("INSERT INTO records (user_id, org_id) VALUES (?, ?)",
                          rows[0]['userid'], orgId)
        response = {
            "status": "success",
            "message": "User added to organisation successfully",
        }
        return response, 200
    except:
        response = {
            "status": "Bad Request",
            "message": "Client error",
            "statusCode": 400
        }
        print(traceback.format_exc())
        return response, 400
