from flask import Flask, request, jsonify
from flask_session import Session

import requests
import os

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route('/')
def home():
    return 'Hello, World! I am here!!!'

@app.route('/api/hello')
def api():
    name = request.args.get("visitor_name")
    ip = request.remote_addr
    city = get_country(ip)
    temp = get_temp(ip)
    output_data = {
        "client_ip": request.remote_addr,
        "location": city,
        "greeting": f"Hello {name}!, the temperature is {temp} degrees Celcius in {city}",
    }
    return jsonify(output_data)

def get_country(ip):
    response = {}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        j_response = response.json()
        country = j_response['city']
        return country
    except Exception:
        print(response)
        return "Unknown"

def get_temp(ip):
    key = os.environ.get('TEMP_API')
    try:
        response = requests.get(f"http://api.weatherapi.com/v1/current.json?key={key}&q={ip}")
        j_response = response.json()
        temp = j_response['current']['temp_c']
        return temp
    except Exception:
        print(response)
        return "Unknown"


if __name__ == "__main__":
    app.run(debug=True)
