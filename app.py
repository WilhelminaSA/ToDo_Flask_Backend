from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Task
from admin import admin_bp  # Admin blueprint import
import jwt

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'  # ✅ Use this consistently

# Initialize DB and register blueprint
db.init_app(app)
app.register_blueprint(admin_bp, url_prefix='/admin')

# Create tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return "Welcome to the To-Do List API with Multiple Databases!"

# ------------------------ AUTH ROUTES ------------------------

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'Missing fields'}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({'error': 'Username or email already exists'}), 409

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing fields'}), 400

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        return jsonify({'message': 'Login successful', 'user_id': user.id, 'username': user.username, 'is_admin': user.is_admin}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

# ------------------------ TASK ROUTES ------------------------

@app.route('/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    user_id = data.get('user_id')
    title = data.get('title')
    description = data.get('description')
    due_date = data.get('due_date')
    priority = data.get('priority', 'Medium')

    if not user_id or not title:
        return jsonify({'error': 'User ID and Title are required'}), 400

    task = Task(
        user_id=user_id,
        title=title,
        description=description,
        due_date=datetime.strptime(due_date, '%Y-%m-%d') if due_date else None,
        priority=priority
    )

    db.session.add(task)
    db.session.commit()

    return jsonify({'message': 'Task created', 'task_id': task.id}), 201

@app.route('/tasks', methods=['GET'])
def get_tasks():
    user_id = request.args.get('user_id')
    completed = request.args.get('completed')
    prio rity = request.args.get('priority')

    query = Task.query.filter_by(user_id=user_id)

    if completed is not None:
        query = query.filter_by(completed=(completed.lower() == 'true'))

    if priority:
        query = query.filter_by(priority=priority)

    tasks = query.all()

    task_list = [dict(
        id=task.id,
        title=task.title,
        description=task.description,
        created_at=task.created_at,
        due_date=task.due_date,
        completed=task.completed,
        priority=task.priority
    ) for task in tasks]

    return jsonify(task_list), 200

@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    data = request.get_json()
    task.title = data.get('title', task.title)
    task.description = data.get('description', task.description)
    task.completed = data.get('completed', task.completed)
    task.due_date = datetime.strptime(data['due_date'], '%Y-%m-%d') if data.get('due_date') else task.due_date
    task.priority = data.get('priority', task.priority)

    db.session.commit()
    return jsonify({'message': 'Task updated'}), 200

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    task = Task.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404

    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted'}), 200

# ------------------------ ADMIN ROUTES (JWT) ------------------------

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    admin_user = User.query.filter_by(email=email).first()

    if admin_user and check_password_hash(admin_user.password, password):
        if admin_user.is_admin:
            token = jwt.encode({
                'admin_id': admin_user.id,
                'is_admin': True,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({'message': 'Login successful', 'token': token}), 200
        else:
            return jsonify({'error': 'User is not an admin'}), 403
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/admin/users', methods=['GET'])
def get_all_users():
    token = request.headers.get('Authorization')

    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'Missing or incorrect token'}), 401

    token = token[7:]  # Remove "Bearer "

    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        if not decoded_token.get('is_admin'):
            return jsonify({'error': 'Unauthorized'}), 403

        users = User.query.all()
        user_list = [dict(
            id=user.id,
            username=user.username,
            email=user.email,
            is_admin=user.is_admin
        ) for user in users]

        return jsonify(user_list), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    admin_id = request.args.get('admin_id')
    admin = User.query.get(admin_id)
    if not admin or not admin.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.is_admin = data.get('is_admin', user.is_admin)

    db.session.commit()
    return jsonify({'message': 'User updated'}), 200

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    admin_id = request.args.get('admin_id')
    admin = User.query.get(admin_id)
    if not admin or not admin.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted'}), 200

@app.route('/admin/tasks', methods=['GET'])
def view_all_tasks():
    admin_id = request.args.get('admin_id')
    admin = User.query.get(admin_id)
    if not admin or not admin.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    tasks = Task.query.all()
    task_list = [dict(
        id=task.id,
        user_id=task.user_id,
        title=task.title,
        description=task.description,
        created_at=task.created_at,
        due_date=task.due_date,
        completed=task.completed,
        priority=task.priority
    ) for task in tasks]

    return jsonify(task_list), 200


# ------------------------ RUN APP ------------------------

if __name__ == '__main__':
    app.run(debug=True)

