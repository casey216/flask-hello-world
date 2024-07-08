import os
import tempfile
from uuid import uuid4

import pytest
from cs50 import SQL

@pytest.fixture
def app():
    from flaskapp import app
    db_fd, db_path = tempfile.mkstemp()
    app.app.config['TESTING'] = True

    with app.app.app_context():
        app.db = SQL("sqlite:///" + db_path)
        app.db.execute("CREATE TABLE users (\
                        userId TEXT PRIMARY KEY UNIQUE NOT NULL,\
                        firstName TEXT NOT NULL,\
                        lastName TEXT NOT NULL,\
                        email TEXT UNIQUE NOT NULL,\
                        password TEXT NOT NULL,\
                        phone TEXT\
                        );")
        app.db.execute("CREATE TABLE organisations (\
                        orgId TEXT UNIQUE PRIMARY KEY NOT NULL,\
                        name TEXT NOT NULL,\
                        description TEXT\
                        );")
        app.db.execute("CREATE TABLE records (\
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,\
                        user_id integer NOT NULL REFERENCES users (userid),\
                        org_id integer NOT NULL REFERENCES organisations (orgid)\
                        );")

    yield app.app


    os.close(db_fd)
    os.unlink(db_path)
    

@pytest.fixture
def client(app):
    return app.test_client()

def register(client, firstName, lastName, email, password, phone):
    return client.post('/auth/register', json={
        "firstName": firstName,
        "lastName": lastName,
        "email": email,
        "password": password,
        "phone": phone,
        }, follow_redirects=True)

def login(client, email, password):
    return client.post('/auth/login', json={
            "email": email,
            "password": password
            }, follow_redirects=True)


def get_user(client, userid, authentication_header):
    return client.get(f'/api/users/{userid}', headers=authentication_header, follow_redirects=True)

# Access token contains correct user identity information
def test_access_token_contains_correct_user_identity_information(app, client):
    from flask_jwt_extended import decode_token

    response = register(client, "John", "Doe", "john.doe@example.com", "password123", "1234567890")

    assert response.status_code == 201
    data = response.get_json()
    assert data['status'] == 'success'
    assert 'accessToken' in data['data']
    with app.app_context():
        decoded_token = decode_token(data['data']['accessToken'])
        print(decode_token)
        assert decoded_token['sub'] == data['data']['user']['userId']

# Access token contains correct user identity information
def test_access_token_expires_at_correct_time(app, client):
    from flask_jwt_extended import decode_token
    import time

    response = register(client, "John", "Doe", "john.doe@example.com", "password123", "1234567890")

    data = response.get_json()
    assert 'accessToken' in data['data']
    with app.app_context():
        decoded_token = decode_token(data['data']['accessToken'])
        assert 'exp' in decoded_token
        time.sleep(300)
        current_time = time.time()
        assert current_time > decoded_token['exp']

def test_users_cant_access_unauthorised_organisations(client):
    user1 = register(client, "Kenechi", "Nzewi", "caseynzewi@gmail.com", "password", "08105472526")
    user2 = register(client, "Kenechi2", "Nzewi2", "caseynzewi2@gmail.com", "password", "08105472526")
    assert 201 == user1.status_code
    data1 = user1.get_json()
    data2 = user2.get_json()
    user1id = data1['data']['user']['userId']
    assert 201 == user2.status_code
    token = data2['data']['accessToken']
    headers = {"authorization": "Bearer " + token}
    response = get_user(client, user1id, headers)
    assert response.status_code == 401
    assert "You do not have Authorisation" == response.get_json()['msg']

def test_successful_register_with_correct_email_and_password(client):
    rv = register(client, "Kenechi", "Nzewi", "caseynzewi2@gmail.com", "password", "08105472526")
    assert 201 == rv.status_code
    data = rv.get_json()
    assert data["status"] == "success"

def test_default_organisation_is_created(app, client):
    from flaskapp.app import db
    rv = register(client, "Kenechi", "Nzewi", "caseynzewi2@gmail.com", "password", "08105472526")
    assert 201 == rv.status_code
    data = rv.get_json()
    assert data["status"] == "success"
    with app.app_context():
        rows = db.execute("SELECT name from organisations WHERE name = ?", "Kenechi's Organisation")
        assert bool(rows) == True

def test_response_contains_user_and_token_details(client):
    rv = register(client, "Kenechi", "Nzewi", "caseynzewi2@gmail.com", "password", "08105472526")
    assert 201 == rv.status_code
    data = rv.get_json()
    assert data["status"] == "success"
    data = data['data']
    assert not data['accessToken'] == False
    user = data['user']
    assert user['firstName'] == "Kenechi"
    assert user['lastName'] == "Nzewi"
    assert user['email'] == "caseynzewi2@gmail.com"
    assert user['phone'] == "08105472526"

def test_log_the_user_in_successfully(client):
    rv = register(client, "Kenechi", "Nzewi", "caseynzewi2@gmail.com", "password", "08105472526")
    assert 201 == rv.status_code

    rv = login(client, "caseynzewi2@gmail.com", "password")
    assert 200 == rv.status_code
    data = rv.get_json()
    assert data["status"] == "success"
    data = data['data']
    assert not data['accessToken'] == False
    user = data['user']
    assert user['firstName'] == "Kenechi"
    assert user['lastName'] == "Nzewi"
    assert user['email'] == "caseynzewi2@gmail.com"
    assert user['phone'] == "08105472526"
    
    rv = login(client, "caseynzewi3@gmail.com", "password")
    assert 401 == rv.status_code

def test_register_with_duplicate_email(client):
    rv = register(client, "Kenechi", "Nzewi", "caseynzewi2@gmail.com", "password", "08105472526")
    assert 201 == rv.status_code
    data = rv.get_json()
    assert data["status"] == "success"

    rv = register(client, "Kenechi", "Nzewi", "caseynzewi2@gmail.com", "password", "08105472526")
    assert 400 == rv.status_code
    data = rv.get_json()
    assert data["message"] == "Registration unsuccessful"
    assert data["status"] == "Bad request"

def test_registration_with_missing_firstname_field(client):
    rv = register(client, None, "Nzewi", "caseynzewi2@gmail.com", "password", "08105472526")
    assert 422 == rv.status_code
    data = rv.get_json()
    assert "errors" in data
    assert any(error["field"] == "firstName" for error in data["errors"])

def test_registration_with_missing_lastname_field(client):
    rv = register(client, "Kenechi", None, "caseynzewi2@gmail.com", "password", "08105472526")
    assert 422 == rv.status_code
    data = rv.get_json()
    assert "errors" in data
    assert any(error["field"] == "lastName" for error in data["errors"])

def test_registration_with_missing_email_field(client):
    rv = register(client, "Kenechi", "Nzewi", None, "password", "08105472526")
    assert 422 == rv.status_code
    data = rv.get_json()
    assert "errors" in data
    assert any(error["field"] == "email" for error in data["errors"])

def test_registration_with_missing_password_field(client):
    rv = register(client, "Kenechi", "Nzewi", "caseynzewi@gmail.com", None, "08105472526")
    assert 422 == rv.status_code
    data = rv.get_json()
    assert "errors" in data
    assert any(error["field"] == "password" for error in data["errors"])
