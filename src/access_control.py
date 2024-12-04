from functools import wraps
from flask_jwt_extended import get_jwt_identity
from flask import jsonify

# Decorador para verificar que el usuario tenga el rol adecuado
def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            current_user = get_jwt_identity()
            if current_user['role'] != role:
                return jsonify(message="You do not have access to this resource"), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Decorador para restringir acceso solo a usuarios autenticados
def user_or_admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        current_user = get_jwt_identity()
        if current_user['role'] not in ['user', 'admin']:
            return jsonify(message="You do not have access to this resource"), 403
        return f(*args, **kwargs)
    return wrapper
