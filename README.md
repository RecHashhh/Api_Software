
# Secure Access Control API

## Overview

This project is a secured Flask-based web application implementing Role-Based Access Control (RBAC) to manage user authentication and authorization. The application integrates several Flask extensions such as `flask_sqlalchemy`, `flask_jwt_extended`, `flask_security`, and `flask_limiter` for database management, JSON Web Token (JWT)-based authentication, role-based access management, and rate limiting.

### Key Features

- **User Authentication and Authorization**: Managed via JWT, with password hashing using `werkzeug.security`.
- **Role-Based Access Control (RBAC)**: Ensures different permissions based on user roles (`admin`, `user`, etc.) using `flask_security`.
- **Rate Limiting**: Uses `flask_limiter` to control the rate of API requests.
- **Audit Logging**: Records all user actions and stores logs for security auditing.
- **Access Requests**: Tracks user requests for access, and admin approves or denies these requests.

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo-url
   cd your-repo-folder
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   Create a `.env` file to hold your secret keys and database connection:
   ```bash
   SECRET_KEY='supersecretkey'
   JWT_SECRET_KEY='supersecretjwtkey'
   DATABASE_URL='sqlite:///rbacSec.db'
   ```

4. **Initialize the database**:
   Inside a Python shell, run the following commands:
   ```python
   from app import db, app
   with app.app_context():
       db.create_all()
   ```

5. **Run the Flask application**:
   ```bash
   flask run
   ```

---

## Application Structure

- **Models**:
  - **User**: Stores user details such as username, email, password, and roles.
  - **Role**: Defines different roles within the system (`admin`, `user`).
  - **AccessLog**: Logs user access attempts to the system for auditing purposes.
  - **AccessRequest**: Tracks requests made by users for special access to areas (e.g., doors).

---

## Key Endpoints

### `POST /register`
**Description**: Registers a new user (admin access required).

**Request Payload**:
```json
{
  "username": "exampleUser",
  "email": "user@example.com",
  "password": "password123"
}
```

**Response**:
- `201 Created`: When a user is successfully registered.
- `409 Conflict`: When the username or email is already in use.
- `400 Bad Request`: When the request body is incomplete.

---

### `POST /login`
**Description**: Logs in a user and returns a JWT token upon successful authentication.

**Request Payload**:
```json
{
  "username": "exampleUser",
  "password": "password123"
}
```

**Response**:
- `200 OK`: On successful login, a JWT token is returned.
- `401 Unauthorized`: When the username or password is incorrect.

---

### `GET /dashboard`
**Description**: Displays the user's dashboard based on their role.

**Access**: 
- `user` role: Standard dashboard.
- `admin` role: Administrative features.

---

### `GET /users`
**Description**: Fetches all registered users (admin access required).

**Access Control**: Restricted to users with the `admin` role.

**Response**:
- `200 OK`: Returns a list of users with their `id`, `username`, and `email`.

---

### `POST /access_request`
**Description**: Allows users to request access to specific locations (e.g., door access).

**Request Payload**:
```json
{
  "location": "Main Entrance",
  "reason": "Working late in the lab."
}
```

**Response**:
- `201 Created`: Access request logged successfully.
- `400 Bad Request`: When required fields are missing.

---

## Security

### JWT Authentication
The application uses `flask_jwt_extended` to handle token-based authentication. Upon login, users are given a JWT token, which they must include in the headers of subsequent requests for verification.

### Rate Limiting
Using `flask_limiter`, the application restricts API requests to 30 per minute per user to prevent abuse.

### Role-Based Access
The app uses Flask-Security's `roles_required` decorator to restrict certain endpoints to users with the appropriate roles. For example, only administrators can access user management endpoints.

### Logging & Audit
All user actions, including access attempts and request statuses, are logged for security and compliance. The logs are stored both in a rotating file and printed to the console in real-time.

---

## Database Models

### `User`
The `User` model represents system users with fields for `username`, `email`, and `password`. The password is hashed for security using `werkzeug`.

**Fields**:
- `id`: Integer, primary key.
- `username`: String, unique and required.
- `email`: String, unique and required.
- `password`: String, hashed.
- `active`: Boolean, user status.
- `roles`: Many-to-Many relationship with `Role`.

---

### `Role`
The `Role` model defines roles such as `admin` or `user`.

**Fields**:
- `id`: Integer, primary key.
- `name`: String, unique role name (e.g., "admin").
- `description`: String, description of the role.

---

### `AccessLog`
Logs user access attempts to resources for auditing purposes.

**Fields**:
- `id`: Integer, primary key.
- `event`: Description of the access event (e.g., "Login attempt").
- `timestamp`: DateTime of the event.
- `door`: String, resource being accessed.
- `user_id`: ForeignKey to the `User` model.

---

### `AccessRequest`
Tracks access requests made by users for specific areas or resources.

**Fields**:
- `id`: Integer, primary key.
- `user_id`: ForeignKey to `User`.
- `status`: Status of the request (e.g., "pending", "approved", "denied").
- `request_time`: Timestamp of the request.
- `location`: Requested location.
- `reason`: Reason for the access request.

---

## Logging & Monitoring

The application implements extensive logging using the Python `logging` module. Every API request is logged, and access logs are stored for auditing purposes. A rotating log file is maintained to prevent file bloating. Audit entries include the user ID, action, status code, and timestamp.

Example log entry:
```json
{
  "user_id": "123",
  "action": "/api/resource",
  "status_code": 200,
  "timestamp": "2024-10-08T12:34:56"
}
```

---

## License

This project is licensed under the MIT License.

---

For more details on configuring your environment and customizing the app, refer to the inline comments in the provided `config.py` file.
