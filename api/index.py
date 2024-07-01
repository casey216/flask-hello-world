from flask import Flask, request, jsonify

import requests
import os

app = Flask(__name__)

app.json.sort_keys = False

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
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        j_response = response.json()
        city = j_response['city']
        return city
    except Exception:
        return "Could not get city!"

def get_temp(ip):
    key = os.environ.get('TEMP_API')
    try:
        response = requests.get(f"http://api.weatherapi.com/v1/current.json?key={key}&q={ip}")
        j_response = response.json()
        temp = j_response['current']['temp_c']
        return temp
    except Exception:
        return "Could not get Temperature"
