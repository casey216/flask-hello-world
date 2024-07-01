from flask import Flask, request, jsonify
from flask_session import Session

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
    return 'Hello, World!'

@app.route('/api/hello')
def api():
    name = request.args.get("visitor_name")
    ip = request.remote_addr
    city = get_country(ip)
    output_data = {
        "ip": request.remote_addr,
        "name": name,
        "city": city
    }
    return jsonify(output_data)

def get_country(ip):
    try:
        response = request.get(f"http://ip-api.com/json/{ip}")
        j_response = response.json()
        country = j_response['country_code']
        return country
    except Exception:
        return "Unknown"

if __name__ == "__main__":
    app.run(debug=True)
