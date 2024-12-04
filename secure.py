import sqlite3
from flask import Flask, request, render_template_string, render_template
import os

app = Flask(__name__)


# Secure: Use environment variables for credentials
def login():
    # Use environment variables for credentials
    username = os.getenv("APP_USERNAME")
    password = os.getenv("APP_PASSWORD")

    # A mock login check
    user_input_username = input("Enter username: ")
    user_input_password = input("Enter password: ")

    if user_input_username == username and user_input_password == password:
        print("Login successful!")
    else:
        print("Invalid credentials!")


# Secure: Use parameterized queries to prevent SQL Injection
def secure_sql_query(username):
    # Use parameterized queries to prevent SQL Injection
    query = "SELECT * FROM users WHERE username = ?"

    # Connect to the database and execute the query
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    cursor.execute(query, (username,))
    results = cursor.fetchall()

    conn.close()
    return results


# Secure: Use Jinja2 autoescaping to prevent XSS
@app.route("/greet", methods=["GET"])
def secure_xss():
    # Get the 'name' parameter from the URL query
    name = request.args.get("name", "")

    # Render the greeting with a template that autoescapes to prevent XSS
    return render_template("greet.html", name=name)


# Secure: Use safe data handling to prevent buffer overflow
def secure_buffer_handling():
    # Define a buffer with limited size
    buffer_size = 10
    buffer = bytearray(buffer_size)

    # Safe copy of data into buffer - prevent overflow by limiting input size
    data = input("Enter data: ")[:buffer_size]  # Limit input size to buffer_size
    for i in range(len(data)):
        buffer[i] = ord(data[i])

    print("Data stored in buffer!")


# Main application route
@app.route("/")
def index():
    # Example usage of vulnerable functions

    # SQL Injection example
    test_username = "admin' OR '1'='1"  # This can exploit SQL injection
    sql_result = secure_sql_query(test_username)
    secure_buffer_handling()
    # Hardcoded credentials example
    login()  # Prompt for username and password with hardcoded credentials

    return "<p>Run the vulnerable functions and test the results!</p>"


if __name__ == "__main__":
    app.run(debug=False)
