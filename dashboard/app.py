from flask import Flask, render_template, jsonify
import json
import os

def create_app():
    app = Flask(__name__)

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    @app.route("/")
    def index():
        return render_template("index.html")
    
    @app.route("/api/alerts")
    def get_alerts():
        report_path = os.path.join(BASE_DIR, "report.json")
        if os.path.exists(report_path):
            with open(report_path) as f:
                data = json.load(f)
            return jsonify(data)
        return jsonify({"alerts": [], "total_alerts": 0})
                        
    return app