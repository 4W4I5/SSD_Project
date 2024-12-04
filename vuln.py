# Extended Vulnerable Code Example

import sqlite3
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)


# Vulnerability: Hardcoded Credentials
def login():
    # Hardcoded credentials - this is insecure and a bad practice
    username = "admin"  # Hardcoded username
    password = "password123"  # Hardcoded password

    # A mock login check
    user_input_username = input("Enter username: ")
    user_input_password = input("Enter password: ")

    if user_input_username == username and user_input_password == password:
        print("Login successful!")
    else:
        print("Invalid credentials!")


# Vulnerability: SQL Injection
def vulnerable_sql_injection(username):
    # This query is vulnerable to SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}'"

    # Connect to the database and execute the query
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute(query)  # Vulnerable to SQL Injection!
    results = cursor.fetchall()

    conn.close()
    return results


# Vulnerability: Cross-Site Scripting (XSS)
@app.route("/greet", methods=["GET"])
def vulnerable_xss():
    # Get the 'name' parameter from the URL query
    name = request.args.get("name", "")

    # Render the greeting with a template vulnerable to XSS
    template = f"<h1>Welcome, {name}!</h1>"
    return render_template_string(template)


# Vulnerability: Buffer Overflow Simulation (in C-style code)
def buffer_overflow_vulnerability():
    # Define a buffer with limited size
    buffer_size = 10
    buffer = bytearray(buffer_size)

    # Unsafe copy of data into buffer - can overflow if input is too large
    data = input("Enter data: ")  # Input from user
    for i in range(len(data)):
        # This can overflow the buffer if data is larger than buffer_size
        buffer[i] = ord(data[i])

    print("Data stored in buffer!")


# Main application route
@app.route("/")
def index():
    # Example usage of vulnerable functions

    # SQL Injection example
    test_username = "admin' OR '1'='1"  # This can exploit SQL injection
    sql_result = vulnerable_sql_injection(test_username)

    # XSS example
    # Visit /greet?name=<script>alert('XSS')</script> to test XSS vulnerability

    # Buffer Overflow example
    buffer_overflow_vulnerability()

    # Hardcoded credentials example
    login()  # Prompt for username and password with hardcoded credentials

    return "<p>Run the vulnerable functions and test the results!</p>"


if __name__ == "__main__":
    app.run(debug=True)
