from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_security import Security, SQLAlchemyUserDatastore
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import verify_jwt_in_request
from flask_security import roles_required
from models import db, AccessLog, AccessRequest, User, Role
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import json

app = Flask(__name__)
app.config.from_object('config.Config')

# Base de datos
db.init_app(app)

# JWT para autenticación
jwt = JWTManager(app)

# Límite de tasa para las solicitudes
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=["30 per minute"])

# Seguridad de roles
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# Configuración del logger para auditoría
logging.basicConfig(
    filename='src/logs/audit.log',  # Archivo de log de auditoría
    level=logging.INFO,  # Nivel de logging
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Crear un handler para imprimir en consola
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Añadir el handler a la aplicación
app.logger.addHandler(console_handler)

# Esto establece el nivel de log de la aplicación
app.logger.setLevel(logging.INFO)

# Lista negra para la invalidación de tokens
blacklist = set()

def log_access(response):
    """Registra el acceso de los usuarios."""
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity() if get_jwt_identity() else 'guest'
    except RuntimeError:
        user_id = 'guest'
    
    app.logger.info(f"User {user_id} accessed {request.url} with status {response.status_code}")
    
    # Registra la auditoría
    log_audit(user_id, request.url, response.status_code)
    return response

def log_audit(user_id, action, status_code):
    """Registra la auditoría de accesos."""
    timestamp = datetime.utcnow()
    log_entry = {
        "user_id": user_id,
        "action": action,
        "status_code": status_code,
        "timestamp": timestamp.isoformat()
    }
    # Guardar el log en el archivo
    app.logger.info(f"Audit Log: {log_entry}")

@app.after_request
def after_request(response):
    return log_access(response)

def role_required(role):
    """Verifica si el usuario tiene el rol adecuado."""
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)

            if user is None or role not in [r.name for r in user.roles]:
                return jsonify({"msg": "Acceso denegado: permisos insuficientes"}), 403

            return fn(*args, **kwargs)
        return decorator
    return wrapper

@app.route('/')
@limiter.limit("4 per hour")
def home():
    return render_template('home.html')  # Renderiza el archivo HTML

@app.route('/register', methods=['POST'])
@limiter.limit("4 per hour")
@jwt_required()
def register():
    """Registra un nuevo usuario."""
    data = request.get_json()
    if not data or not all(k in data for k in ('username', 'email', 'password')):
        return jsonify({'message': 'Datos incompletos'}), 400

    # Verificar si el nombre de usuario ya existe
    existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
    if existing_user:
        return jsonify({'message': 'El nombre de usuario o el correo electrónico ya están en uso'}), 409

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Usuario registrado exitosamente'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error al registrar el usuario', 'error': str(e)}), 400

def log_login_attempt(email, success):
    """Logea el intento de inicio de sesión."""
    if success:
        app.logger.info(f'Inicio de sesión exitoso: {email}.')
    else:
        app.logger.warning(f'Intento de inicio de sesión fallido para: {email}.')

@app.route('/login1', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def login():
    """Inicia sesión para un usuario."""
    if request.method == 'POST':
        data = request.form
        username = data.get('username')  # Cambia email a username
        password = data.get('password')

        if not username or not password:
            app.logger.warning('Intento de inicio de sesión fallido: Campos vacíos.')
            flash('Por favor, ingresa ambos campos.', 'danger')
            return render_template('login.html')

        # Busca al usuario por nombre de usuario
        user = User.query.filter_by(username=username).first()

        if user:
            app.logger.info(f'Usuario encontrado: {user.username}. Intentando verificar contraseña.')
            if check_password_hash(user.password, password):
                access_token = create_access_token(identity=user.id)
                session['user_id'] = user.id
                session['username'] = user.username
                session['roles'] = [role.name for role in user.roles]  # Guardar roles en la sesión
                log_login_attempt(username, success=True)  # Log de éxito
                return redirect(url_for('dashboard'))  # Redirigir al dashboard
            else:
                log_login_attempt(username, success=False)  # Log de fallo
                flash('Contraseña incorrecta', 'danger')
        else:
            log_login_attempt(username, success=False)  # Log de fallo
            flash('Usuario no encontrado', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
@limiter.limit("4 per hour")
def dashboard():
    """Página de inicio del dashboard."""
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirigir si no está autenticado

    user = User.query.get(session['user_id'])
    roles = session.get('roles', [])  # Obtener roles desde la sesión

    # Verifica si el usuario tiene el rol de administrador
    is_admin = 'admin' in roles  # Cambia 'admin' al nombre del rol correspondiente

    return render_template('dashboard.html', user=user, is_admin=is_admin, roles=roles)

@app.route('/users', methods=['GET'])
@limiter.limit("4 per hour")
def get_all_users():
    """Obtiene todos los usuarios."""
    users = User.query.all()
    return jsonify([{"id": user.id, "username": user.username, "email": user.email} for user in users])

@app.route('/register_page')
@limiter.limit("4 per hour")
def register_page():
    """Muestra la página de registro de nuevos usuarios."""
    return render_template('register.html')

@app.route('/logout')
@jwt_required()
def logout():
    jti = get_jwt_identity()
    blacklist.add(jti)
    session.clear()  # Limpiar la sesión
    return jsonify({"msg": "Sesión cerrada exitosamente"}), 200

@app.route('/bitacora', methods=['GET'])
@limiter.limit("4 per hour")
@jwt_required()
@roles_required('user')
def bitacora():
    """Obtiene los registros de acceso."""
    logs = AccessLog.query.all()
    return jsonify([log.event for log in logs])

@app.route('/solicitar_acceso', methods=['POST'])
@jwt_required()
@roles_required('user')
@limiter.limit("100 per hour")
def solicitar_acceso():
    """Crea una nueva solicitud de acceso."""
    data = request.get_json()
    if not data or not all(k in data for k in ('location', 'reason')):
        return jsonify({'message': 'Datos incompletos'}), 400

    # Crear la solicitud de acceso
    new_request = AccessRequest(user_id=get_jwt_identity(), location=data['location'], reason=data['reason'], status='pending')
    
    try:
        db.session.add(new_request)
        db.session.commit()
        return jsonify({'message': 'Solicitud creada exitosamente', 'request': new_request.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error al crear la solicitud', 'error': str(e)}), 400

@app.route('/access_requests', methods=['GET'])
@limiter.limit("4 per hour")
@jwt_required()
@role_required('admin')
def get_all_requests():
    """Obtiene todas las solicitudes de acceso."""
    requests = AccessRequest.query.all()
    return jsonify([req.to_dict() for req in requests])

@app.route('/deny_request/<int:request_id>', methods=['POST'])
@limiter.limit("4 per hour")
@jwt_required()
@role_required('admin')
def deny_request(request_id):
    """Niega una solicitud de acceso."""
    req = AccessRequest.query.get_or_404(request_id)
    req.status = 'denied'

    try:
        db.session.commit()
        return jsonify({'message': 'Solicitud denegada exitosamente'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error al denegar la solicitud', 'error': str(e)}), 400

@app.route('/allow_request/<int:request_id>', methods=['POST'])
@limiter.limit("4 per hour")
@jwt_required()
@role_required('admin')
def allow_request(request_id):
    """Aprueba una solicitud de acceso."""
    req = AccessRequest.query.get_or_404(request_id)
    req.status = 'approved'

    try:
        db.session.commit()
        return jsonify({'message': 'Solicitud aprobada exitosamente'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Error al aprobar la solicitud', 'error': str(e)}), 400


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Crear las tablas de la base de datos

        # Crear roles iniciales si no existen
        existing_role = db.session.query(Role).filter_by(name='admin').first()
        if not existing_role:
            admin_role = Role(name='admin', description='Administrator with full access')
            user_role = Role(name='user', description='Regular user with limited access')

            db.session.add(admin_role)
            db.session.add(user_role)
            db.session.commit()
            print("Roles 'admin' y 'user' creados.")
        else:
            print("Role 'admin' ya existe.")

        # Comprobar si los usuarios ya existen
        existing_admin_user = User.query.filter_by(username='admin').first()
        existing_regular_user = User.query.filter_by(username='user').first()

        if not existing_admin_user:
            hashed_admin_password = generate_password_hash('adminpassword', method='pbkdf2:sha256')
            admin_user = User(username='admin', email='admin@example.com', password=hashed_admin_password, active=True)
            admin_user.roles.append(Role.query.filter_by(name='admin').first())
            print(f"Usuario 'admin' creado exitosamente con hash: {hashed_admin_password}")

            db.session.add(admin_user)
            db.session.commit()

            print("Usuario 'admin' creado exitosamente.")
        else:
            print("El usuario 'admin' ya existe.")
            
            
        if not existing_regular_user:
            # Crear un usuario regular
            hashed_user_password = generate_password_hash('userpassword', method='pbkdf2:sha256')
            regular_user = User(username='user', email='user@example.com', password=hashed_user_password, active=True)
            regular_user.roles.append(Role.query.filter_by(name='user').first())

            db.session.add(regular_user)
            print("Usuario 'user' creado exitosamente.")
        else:
            print("El usuario 'user' ya existe.")

        # Intentar hacer commit
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()  # Revertir cualquier cambio si ocurre un error
            print(f"Error al crear usuarios: {str(e)}")

    app.run(debug=True, host='0.0.0.0', port=5002)