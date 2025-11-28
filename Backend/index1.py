import json
import time
import uuid
import datetime
from functools import wraps
from flask import Flask, request, jsonify

# --- Configuration ---
# NOTE: In a real application, replace this with a secure key from a vault/KMS
SECRET_KEY = "super-secret-hacklaunch-key-321"
# Token validity period (e.g., 24 hours)
TOKEN_EXPIRY_HOURS = 24 

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY

# --- Mock In-Memory Database (Data Model Implementation) ---
# Simulates a persistent database for Users, Projects, and Deployments
MOCK_DB = {
    "users": {},  # { user_id: { email, password_hash, roles, institution } }
    "projects": {}, # { project_id: { owner_id, name, repo_url, framework, status, metadata } }
    "deployments": {} # { deployment_id: { project_id, status, logs, start_time, end_time } }
}

# Add a mock admin user for testing
MOCK_DB['users']['admin-123'] = {
    'id': 'admin-123',
    'email': 'student@hack.edu',
    'password_hash': 'hashed_password', # In production, use bcrypt/argon2
    'roles': ['student', 'admin'],
    'institution': 'Hack University'
}

# --- Utility Functions: JWT and Authentication ---

def generate_jwt(user_id, roles):
    """Generates a JSON Web Token for the user."""
    payload = {
        'user_id': user_id,
        'roles': roles,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRY_HOURS),
        'iat': datetime.datetime.utcnow()
    }
    # Using jwt.encode is required in a real setup, but for this single-file demo,
    # we'll use base64 encoding to simulate token structure without external libs.
    # In a real Flask app, you would use: jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    token_data = json.dumps(payload)
    return f"MOCK_JWT.{token_data}.SIGNATURE" 

def decode_jwt(token):
    """Decodes a MOCK JWT and returns the payload."""
    try:
        # Simulate decoding the middle payload part
        payload_str = token.split('.')[1]
        payload = json.loads(payload_str)
        
        # Check expiry
        if payload['exp'] < datetime.datetime.utcnow().timestamp():
            return None # Token expired
        
        return payload
    except Exception:
        return None

def auth_required(f):
    """Decorator to enforce authentication on routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid Authorization header."}), 401

        token = auth_header.split(' ')[1]
        payload = decode_jwt(token)

        if not payload:
            return jsonify({"error": "Invalid or expired token."}), 401

        # Attach user info to request context
        request.user = payload
        return f(*args, **kwargs)
    return decorated

def role_required(role):
    """Decorator to enforce specific user roles."""
    def decorator(f):
        @wraps(f)
        @auth_required
        def decorated_function(*args, **kwargs):
            if role not in request.user.get('roles', []):
                return jsonify({"error": f"Access denied. Requires role: {role}"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- I. Auth Service Endpoints ---

@app.route('/auth/signup', methods=['POST'])
def signup():
    """Handles user registration with email/password (or mock SSO data)."""
    data = request.json
    email = data.get('email')
    password = data.get('password') # Use bcrypt in production

    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400

    # Check if user exists (simplified check)
    if any(u['email'] == email for u in MOCK_DB['users'].values()):
        return jsonify({"error": "User already exists."}), 409

    user_id = str(uuid.uuid4())
    MOCK_DB['users'][user_id] = {
        'id': user_id,
        'email': email,
        'password_hash': password, # Mock hash
        'roles': ['student'],
        'institution': data.get('institution', 'unknown')
    }
    token = generate_jwt(user_id, ['student'])
    return jsonify({"message": "User created successfully.", "token": token}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    """Handles user login and token issuance."""
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Find user (simplified password check)
    user = next((u for u in MOCK_DB['users'].values() if u['email'] == email and u['password_hash'] == password), None)

    if not user:
        return jsonify({"error": "Invalid credentials."}), 401

    token = generate_jwt(user['id'], user['roles'])
    return jsonify({"message": "Login successful.", "token": token, "user_id": user['id'], "roles": user['roles']})

# --- II. Project Service Endpoints ---

@app.route('/projects', methods=['GET'])
@auth_required
def get_projects():
    """Retrieves all projects owned by the authenticated user."""
    user_id = request.user['user_id']
    user_projects = [
        p for p in MOCK_DB['projects'].values() if p['owner_id'] == user_id
    ]
    return jsonify(user_projects)

@app.route('/projects', methods=['POST'])
@auth_required
def create_project():
    """Creates a new project entry."""
    data = request.json
    if not data.get('name') or not data.get('repo_url'):
        return jsonify({"error": "Project name and repository URL are required."}), 400

    project_id = str(uuid.uuid4())
    new_project = {
        'id': project_id,
        'owner_id': request.user['user_id'],
        'name': data['name'],
        'repo_url': data['repo_url'],
        'framework': data.get('framework', 'Auto-detected'),
        'status': 'NotDeployed',
        'metadata': {'creation_date': datetime.datetime.now().isoformat()}
    }
    MOCK_DB['projects'][project_id] = new_project
    return jsonify(new_project), 201

@app.route('/projects/<project_id>', methods=['GET'])
@auth_required
def get_project(project_id):
    """Retrieves a single project."""
    project = MOCK_DB['projects'].get(project_id)
    if not project or project['owner_id'] != request.user['user_id']:
        return jsonify({"error": "Project not found or access denied."}), 404
    return jsonify(project)

# --- III. Deployment Orchestration Simulation ---

DEPLOYMENT_STEPS = [
    # Checkout and Setup
    {"msg": "Initializing CI/CD runner environment...", "duration": 1.0, "level": "INFO"},
    {"msg": "Connecting to Git provider and checking out repository...", "duration": 1.5, "level": "INFO"},
    {"msg": "Auto-detecting project runtime (Node.js/Python)...", "duration": 1.0, "level": "INFO"},
    
    # Combined Build
    {"msg": "--- STARTING COMBINED BUILD ---", "duration": 0.5, "level": "STEP"},
    {"msg": "Running *Frontend Build* (npm run build/vite build)...", "duration": 2.0, "level": "INFO"},
    {"msg": "Minifying and optimizing static assets (SPA artifacts generated)...", "duration": 1.5, "level": "INFO"},
    {"msg": "Copying static frontend assets into backend server folder (/server/public)...", "duration": 1.0, "level": "INFO"},
    {"msg": "Running *Backend Build* (pip install/npm install)...", "duration": 2.5, "level": "INFO"},
    
    # Security Scan and Deployment
    {"msg": "Running static security analysis (SAST/Secret Scanning)...", "duration": 2.0, "level": "SECURITY"},
    {"msg": "Configuring backend catch-all route to serve embedded frontend index.html...", "duration": 1.0, "level": "INFO"},
    {"msg": "Provisioning immutable container and deploying unified package...", "duration": 3.0, "level": "DEPLOY"},
    {"msg": "Deployment complete. Final health checks passed.", "duration": 0.0, "level": "SUCCESS"},
]

def simulate_deployment_pipeline(project_id, deployment_id):
    """
    Simulates the CI/CD pipeline and generates auditable logs.
    In a real system, this would trigger an asynchronous worker (Kubernetes Job/Cloud Function).
    """
    logs = []
    start_time = time.time()
    
    # Update project status to Building
    MOCK_DB['projects'][project_id]['status'] = 'Building'
    
    for step in DEPLOYMENT_STEPS:
        msg = f"[{step['level']}] {step['msg']}"
        print(f"[{datetime.datetime.now().isoformat()}] Deployment {deployment_id}: {msg}") # Server Log
        
        # Add to deployment logs
        logs.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "message": step['msg'],
            "level": step['level']
        })
        time.sleep(step['duration'] * 0.5) # Speed up simulation

    end_time = time.time()
    
    # Final updates
    MOCK_DB['projects'][project_id]['status'] = 'Live'
    MOCK_DB['deployments'][deployment_id] = {
        'project_id': project_id,
        'status': 'SUCCESS',
        'logs': logs,
        'start_time': datetime.datetime.fromtimestamp(start_time).isoformat(),
        'end_time': datetime.datetime.fromtimestamp(end_time).isoformat(),
        'duration_seconds': round(end_time - start_time, 2),
        'deployment_url': f"https://{MOCK_DB['projects'][project_id]['name'].lower().replace(' ', '-')}.hacklaunch.app"
    }

@app.route('/deployments', methods=['POST'])
@auth_required
def trigger_deployment():
    """Triggers the deployment pipeline for a project."""
    data = request.json
    project_id = data.get('project_id')

    project = MOCK_DB['projects'].get(project_id)
    if not project or project['owner_id'] != request.user['user_id']:
        return jsonify({"error": "Project not found or access denied."}), 404

    deployment_id = str(uuid.uuid4())

    # Initial state for the deployment record
    MOCK_DB['deployments'][deployment_id] = {
        'project_id': project_id,
        'status': 'QUEUED',
        'logs': [{"timestamp": datetime.datetime.now().isoformat(), "message": "Deployment queued.", "level": "INFO"}],
        'start_time': datetime.datetime.now().isoformat(),
        'deployment_url': 'N/A'
    }

    # Simulate immediate worker start (synchronous execution for this file)
    try:
        simulate_deployment_pipeline(project_id, deployment_id)
    except Exception as e:
        # Simulate failure
        MOCK_DB['projects'][project_id]['status'] = 'Error'
        MOCK_DB['deployments'][deployment_id]['status'] = 'FAILED'
        MOCK_DB['deployments'][deployment_id]['logs'].append({
            "timestamp": datetime.datetime.now().isoformat(),
            "message": f"Deployment failed: {str(e)}",
            "level": "ERROR"
        })
        return jsonify({"message": "Deployment failed to start.", "deployment_id": deployment_id}), 500


    # Return the initial deployment status (which is quickly updated by the sync process)
    return jsonify({
        "message": "Deployment triggered successfully.",
        "deployment_id": deployment_id,
        "status": MOCK_DB['deployments'][deployment_id]['status'],
        "deployment_url": MOCK_DB['deployments'][deployment_id].get('deployment_url')
    }), 202

@app.route('/logs/subscribe/<deployment_id>', methods=['GET'])
@auth_required
def get_deployment_logs(deployment_id):
    """
    Retrieves the complete log history for a deployment.
    
    NOTE: This API route would typically be handled by a *WebSocket (WSS)* or 
    *Server-Sent Events (SSE)* connection in a real application to enable
    real-time streaming, as required by your specification. This synchronous
    route provides the current log snapshot.
    """
    deployment = MOCK_DB['deployments'].get(deployment_id)
    if not deployment:
        return jsonify({"error": "Deployment not found."}), 404
    
    # In a real system, this would stream the logs line by line
    return jsonify(deployment['logs'])


@app.route('/artifacts/<deployment_id>', methods=['GET'])
@auth_required
def get_deployment_artifacts(deployment_id):
    """Generates portfolio-ready artifacts (mock data)."""
    deployment = MOCK_DB['deployments'].get(deployment_id)
    if not deployment or deployment['status'] != 'SUCCESS':
        return jsonify({"error": "Deployment artifacts not ready."}), 404
        
    project = MOCK_DB['projects'][deployment['project_id']]

    return jsonify({
        "project_name": project['name'],
        "deployment_url": deployment['deployment_url'],
        "readme_snippet": "This project, built in 48 hours, features real-time data visualization and secure OAuth login. A true testament to modern web development.",
        "badge_url": f"https://placehold.co/150x50/10b981/ffffff?text=Deployed%20|%20Live",
        "embed_code": f"<iframe src='{deployment['deployment_url']}' height='400px' width='100%'></iframe>"
    })


# --- Startup ---
if __name__ == '_main_':
    # To run this API:
    # 1. Save this file as app.py
    # 2. Run: flask run
    # 3. Access at http://127.0.0.1:5000/auth/login (POST)
    print("----------------------------------------------------------")
    print(" HackLaunch Backend Core API (Flask) is running.")
    print(" Use the /auth/signup and /auth/login endpoints to generate a token.")
    print(" Use the sample user: student@hack.edu / hashed_password")
    print("----------------------------------------------------------")
    app.run(debug=True)