from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flasgger import Swagger
from dotenv import load_dotenv
import os

load_dotenv()  # Load variables from .env file

user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
db_name = os.getenv("DB_NAME")

app = Flask(__name__)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{user}:{password}@{host}/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
app.config['JWT_BLACKLIST_ENABLED'] = True

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
Swagger(app)
blacklist = set()

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student', 'faculty', 'contributor'

# Assignment Model
class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    feedback = db.Column(db.Text, nullable=True)

with app.app_context():
    db.create_all()

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """
    Logout user (Invalidate JWT token)
    ---
    tags:
      - User Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: Successfully logged out
    """
    jti = get_jwt()['jti']
    blacklist.add(jti)
    return jsonify({'message': 'Successfully logged out'}), 200

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    return jwt_payload['jti'] in blacklist
# User Registration
@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - User Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
            - role
          properties:
            username:
              type: string
              example: "testuser"
            password:
              type: string
              example: "password123"
            role:
              type: string
              enum: ["student", "faculty", "contributor"]
              example: "student"
    responses:
      201:
        description: User registered successfully
      400:
        description: Bad request
    """
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

# User Login
@app.route('/login', methods=['POST'])
def login():
    """
    User Login
    ---
    tags:
      - User Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
              example: "testuser"
            password:
              type: string
              example: "password123"
    responses:
      200:
        description: Successful login
        schema:
          type: object
          properties:
            access_token:
              type: string
              example: "jwt_token_here"
      401:
        description: Invalid credentials
    """
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.username, additional_claims={"role": user.role})
        return jsonify({'access_token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# Get All Users (Admin only)
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    """
    Get all users (Admin only)
    ---
    tags:
      - Users
    security:
      - Bearer: []
    responses:
      200:
        description: List of users
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              username:
                type: string
              role:
                type: string
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({'message': 'Unauthorized'}), 403
    users = User.query.all()
    return jsonify([{'id': user.id, 'username': user.username, 'role': user.role} for user in users])

# Upload Assignment
@app.route('/assignments/upload', methods=['POST'])
@jwt_required()
def upload_assignment():
    """
    Upload an assignment (Students only)
    ---
    tags:
      - Assignments
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - title
            - content
          properties:
            title:
              type: string
            content:
              type: string
    responses:
      201:
        description: Assignment uploaded successfully
    """
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    if user.role != 'student':
        return jsonify({'message': 'Only students can upload assignments'}), 403
    data = request.get_json()
    new_assignment = Assignment(student_id=user.id, title=data['title'], content=data['content'])
    db.session.add(new_assignment)
    db.session.commit()
    return jsonify({'message': 'Assignment uploaded successfully'}), 201

# Get All Assignments
@app.route('/assignments', methods=['GET'])
@jwt_required()
def get_assignments():
    """
    Get all assignments
    ---
    tags:
      - Assignments
    security:
      - Bearer: []
    responses:
      200:
        description: List of assignments
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              student_id:
                type: integer
              title:
                type: string
              content:
                type: string
              feedback:
                type: string
    """
    assignments = Assignment.query.all()
    return jsonify([
        {'id': a.id, 'student_id': a.student_id, 'title': a.title, 'content': a.content, 'feedback': a.feedback}
        for a in assignments
    ])

# Provide Feedback (Faculty only)
@app.route('/assignments/feedback/<int:assignment_id>', methods=['POST'])
@jwt_required()
def give_feedback(assignment_id):
    """
    Provide feedback on an assignment (Faculty only)
    ---
    tags:
      - Assignments
    security:
      - Bearer: []
    parameters:
      - name: assignment_id
        in: path
        type: integer
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - feedback
          properties:
            feedback:
              type: string
    responses:
      200:
        description: Feedback added successfully
    """
    claims = get_jwt()
    if claims.get("role") != "faculty":
        return jsonify({'message': 'Only faculty can provide feedback'}), 403
    data = request.get_json()
    assignment = Assignment.query.get(assignment_id)
    if not assignment:
        return jsonify({'message': 'Assignment not found'}), 404
    assignment.feedback = data['feedback']
    db.session.commit()
    return jsonify({'message': 'Feedback added successfully'})

# Protected Route Example
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    """
    Protected Route - Requires Authentication
    ---
    tags:
      - Protected Routes
    security:
      - Bearer: []
    responses:
      200:
        description: Access granted
        schema:
          type: object
          properties:
            message:
              type: string
              example: "Access granted"
            user:
              type: string
              example: "testuser"
            role:
              type: string
              example: "student"
    """
    current_user = get_jwt_identity()
    claims = get_jwt()  # Retrieves additional claims
    user_role = claims.get("role", "Unknown")  # Extracts role from token
    return jsonify({'message': 'Access granted', 'user': current_user, "role": user_role})

if __name__ == '__main__':
    app.run(debug=True)
