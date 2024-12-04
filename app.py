from flask import Flask, request, render_template, redirect, url_for
from werkzeug.utils import secure_filename
import os
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
import json
from flask_sqlalchemy import SQLAlchemy
import logging

# Import the scan functions
from bandit_scan import run_bandit_scan
from semgrep_scan import run_semgrep_scan
from generate_report import generate_report

# Initialize the Flask application
app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///scan_results.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database
db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Define the ScanResult model
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    results = db.Column(db.Text)  # Store the results as JSON string

    def __init__(self, filename, results):
        self.filename = filename
        self.results = json.dumps(results)

    def get_results(self):
        return json.loads(self.results)

# Create the database tables
with app.app_context():
    db.create_all()

# Load the tokenizer and model
with open("data/tokenizer.pickle", "rb") as handle:
    tokenizer = pickle.load(handle)

# Maximum length of sequences (should match the one used during training)
maxlen = 100

# Load the pre-trained model
model = tf.keras.models.load_model("malicious_script_detector.h5")

# Class mapping for model predictions
class_mapping = {0: "Benign", 1: "XSS", 2: "SQL Injection"}

@app.route("/")
def index():
    # Redirect to the upload page
    return redirect(url_for("upload_code"))

@app.route("/upload", methods=["GET", "POST"])
def upload_code():
    if request.method == "POST":
        if "code_file" not in request.files:
            return "No file part"
        file = request.files["code_file"]
        if file.filename == "":
            return "No selected file"
        filename = secure_filename(file.filename)
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)
        return redirect(url_for("scan_code", filename=filename))
    return render_template("upload.html")

@app.route("/scan/<filename>")
def scan_code(filename):
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    logging.debug(f"Scanning file at: {filepath}")

    if not os.path.isfile(filepath):
        logging.error(f"File not found: {filepath}")
        return render_template("upload.html", prediction="Uploaded file not found.")

    file_extension = os.path.splitext(filename)[1].lower()

    # Initialize results list
    combined_results = []

    # Run Bandit scan only on Python files
    if file_extension == ".py":
        bandit_results = run_bandit_scan(filepath)
        logging.debug(f"Bandit results: {bandit_results}")
        combined_results.extend(bandit_results)
    else:
        # Include a message if Bandit is skipped
        combined_results.append(
            {
                "issue": "Bandit scan skipped",
                "severity": "INFO",
                "filename": filename,
                "line_number": "N/A",
                "suggestion": "Bandit scans only Python files.",
            }
        )

    # Run Semgrep scan
    semgrep_results = run_semgrep_scan(filepath)
    logging.debug(f"Semgrep results: {semgrep_results}")
    combined_results.extend(semgrep_results)

    # AI Model Prediction
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            code_content = f.read()
    except Exception as e:
        return render_template("upload.html", prediction=f"Error reading file: {e}")

    if not code_content.strip():
        return render_template("upload.html", prediction="The uploaded file is empty.")

    # Preprocess the input
    new_sequence = tokenizer.texts_to_sequences([code_content])
    new_padded_sequence = pad_sequences(new_sequence, padding="post", maxlen=maxlen)

    # Predict the class of the new sample
    prediction = model.predict(new_padded_sequence)
    predicted_class = prediction.argmax(axis=-1)[0]
    predicted_label = class_mapping.get(predicted_class, "Unknown")

    # Prepare AI result
    ai_result = {
        "issue": (
            f"Detected {predicted_label}"
            if predicted_label != "Benign"
            else "No Vulnerability Detected"
        ),
        "severity": "HIGH" if predicted_label != "Benign" else "LOW/None",
        "confidence": f"{max(prediction[0]):.2f}",
        "suggestion": (
            "Review this code for potential vulnerabilities."
            if predicted_label != "Benign"
            else "No action needed."
        ),
    }
    combined_results.append(ai_result)

    # Save to database
    scan_result = ScanResult(filename=filename, results=combined_results)
    db.session.add(scan_result)
    db.session.commit()

    # Clean up the uploaded file
    os.remove(filepath)

    return render_template(
        "results.html", results=combined_results, scan_id=scan_result.id
    )

@app.route("/report/<int:scan_id>")
def download_report(scan_id):
    scan_result = ScanResult.query.get(scan_id)
    if not scan_result:
        return "Scan result not found."
    report_name = generate_report(scan_result)
    return redirect(url_for("static", filename="reports/" + report_name))

if __name__ == "__main__":
    app.run(debug=True)
