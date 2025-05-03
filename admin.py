from flask import Blueprint, request, jsonify
from models import db, User
from werkzeug.security import generate_password_hash
from flask import current_app
import jwt
from datetime import datetime, timedelta

# Create a blueprint for the admin routes
admin_bp = Blueprint('admin_bp', __name__)

# Route for admin signup
@admin_bp.route('/signup', methods=['POST'])
def admin_signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    existing_admin = User.query.filter_by(email=email).first()
    if existing_admin:
        return jsonify({'error': 'Admin already exists'}), 409

    hashed_password = generate_password_hash(password)
    new_admin = User(email=email, password=hashed_password, is_admin=True)

    db.session.add(new_admin)
    db.session.commit()

    return jsonify({'message': 'Admin created successfully'}), 201

# Enable or disable a user account (requires JWT from admin)
@admin_bp.route('/users/<int:user_id>/status', methods=['PUT'])
def toggle_user_status(user_id):
    token = request.headers.get('Authorization')

    if not token or not token.startswith('Bearer '):
        return jsonify({'error': 'Missing or incorrect token'}), 401

    token = token[7:]
    try:
        decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        if not decoded_token.get('is_admin'):
            return jsonify({'error': 'Unauthorized'}), 403

        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        data = request.get_json()
        enable = data.get('is_active', True)
        user.is_active = enable

        db.session.commit()
        return jsonify({'message': f'User has been {"enabled" if enable else "disabled"} successfully'}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


@admin_bp.route('/admin/users', methods=['GET'])
def get_all_users():
    users = User.query.all()
    user_list = []
    for user in users:
        user_list.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        })
    return jsonify(user_list), 200

