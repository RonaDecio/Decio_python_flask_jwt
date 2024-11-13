from flask import Flask, jsonify, request
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Secret key for encoding and decoding JWT
SECRET_KEY = 'your_secret_key'

# In-memory "database" for users (for demonstration purposes)
users_db = {}


# Helper function to create a JWT
def create_jwt(user_id):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    payload = {
        'sub': user_id,  # Subject claim (username)
        'exp': expiration_time
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token


# Route to get a JWT (For demonstration, will just return a pre-generated token)
@app.route('/get-jwt', methods=['GET'])
def get_jwt():
    token = request.headers.get('Authorization')  # Expecting JWT in the Authorization header
    if token:
        try:
            # Decode JWT to verify its validity
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            return jsonify({"message": "Token is valid", "user": decoded_token['sub']}), 200
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
    return jsonify({"error": "Token is missing"}), 400


# Route to set a JWT (Login or create JWT by providing username and password)
@app.route('/set-jwt', methods=['POST'])
def set_jwt():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username not in users_db:
        return jsonify({"error": "User not found"}), 404

    user = users_db[username]

    if not check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid password"}), 401

    # Create JWT token
    token = create_jwt(username)
    return jsonify({"message": "JWT created", "token": token}), 200


# Route to handle user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username not in users_db:
        return jsonify({"error": "User not found"}), 404

    user = users_db[username]

    if not check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid password"}), 401

    # Create JWT token on successful login
    token = create_jwt(username)
    return jsonify({"message": "Login successful", "token": token}), 200


# Route to handle user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users_db:
        return jsonify({"error": "Username already exists"}), 400

    # Hash the password before storing
    hashed_password = generate_password_hash(password)
    users_db[username] = {'password': hashed_password}

    return jsonify({"message": "User registered successfully"}), 201


if __name__ == '__main__':
    app.run(debug=True)
