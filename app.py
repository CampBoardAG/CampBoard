from flask import jsonify, Flask, render_template, request, redirect, session, url_for, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import os
from functools import wraps
from app import db, User, bcrypt
import sqlite3
import hashlib

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# Initialize Flask app
app = Flask(__name__,
           template_folder='web',
           static_folder='web',
           static_url_path='')

# Configuration
app.secret_key = 'your-secret-key-here'  # Change this in production!
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB file size limit
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# MongoDB Connection
client = MongoClient('mongodb://localhost:27017/')
db = client['college_app']
users_collection = db['users']
applications_collection = db['applications']

# Helper Functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_uploaded_file(field_name):
    file = request.files.get(field_name)
    if file and file.filename:
        if not allowed_file(file.filename):
            raise ValueError(f'Invalid file type for {field_name}')
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return filename
    return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        if not all([username, email, password, confirm_password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
        
        if users_collection.find_one({'email': email}):
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        if users_collection.find_one({'username': username}):
            flash('Username already taken!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        user = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'created_at': datetime.utcnow()
        }
        user_id = users_collection.insert_one(user).inserted_id

        session['user_id'] = str(user_id)
        flash('Registration successful!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = users_collection.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('/user1.html')

@app.route('/data')
@login_required
def data_form():
    return render_template('data.html')

@app.route('/submit', methods=['GET'])
@login_required
def submit_form():
    try:
        # Handle file uploads
        required_files = {
            'passport-photo': 'passport_photo',
            'signature': 'signature',
            '10th-marksheet': 'marksheet_10th',
            '12th-marksheet': 'marksheet_12th',
            'adhar-copy': 'id_proof'
        }
        
        file_paths = {}
        for form_field, db_field in required_files.items():
            file = request.files.get(form_field)
            if not file or file.filename == '':
                return jsonify({'success': False, 'error': f'Missing required file: {form_field}'}), 400
            
            if not allowed_file(file.filename):
                return jsonify({'success': False, 'error': f'Invalid file type for {form_field}'}), 400
            
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            file_paths[db_field] = filename

        # Create application document
        application = {
            'user_id': ObjectId(session['user_id']),
            'created_at': datetime.utcnow(),
            # Personal Details
            'name': request.form.get('name'),
            'age': int(request.form.get('age')),
            'contact_number': request.form.get('contact-number'),
            'email': request.form.get('email'),
            'course': request.form.get('course'),
            'government_id': request.form.get('government-id'),
            'id_number': request.form.get('id-number'),
            'pincode': request.form.get('pincode'),
            'city': request.form.get('city'),
            'state': request.form.get('state'),
            'address': request.form.get('address'),
            # Education Details
            'board_of_education': request.form.get('board-of-ed'),
            'secondary_school': request.form.get('secondary-school'),
            'secondary_roll': request.form.get('secondary-roll'),
            'secondary_marks': float(request.form.get('secondary-marks')),
            'senior_secondary_school': request.form.get('senior-secondary-school'),
            'senior_subjects': request.form.get('senior-subjects'),
            'senior_roll': request.form.get('senior-roll'),
            'senior_marks': float(request.form.get('senior-marks')),
            # Family Details
            'father_name': request.form.get('father-name'),
            'father_contact': request.form.get('father-contact'),
            'father_email': request.form.get('father-email'),
            'father_occupation': request.form.get('father-occupation'),
            'mother_name': request.form.get('mother-name'),
            'mother_contact': request.form.get('mother-contact'),
            'mother_email': request.form.get('mother-email'),
            'mother_occupation': request.form.get('mother-occupation'),
            'annual_income': float(request.form.get('annual-income')),
            # Exam Centers
            'exam_center_1': request.form.get('exam-center-1'),
            'exam_center_2': request.form.get('exam-center-2'),
            'exam_center_3': request.form.get('exam-center-3'),
            'exam_center_4': request.form.get('exam-center-4'),
            'exam_center_5': request.form.get('exam-center-5'),
            # Document Paths
            **file_paths
        }
        
        # Insert application into MongoDB
        result = applications_collection.insert_one(application)
        
        return jsonify({
            'success': True,
            'message': 'Application submitted successfully!',
            'application_id': str(result.inserted_id)
        })
    
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/application/<application_id>')
@login_required
def view_application(application_id):
    try:
        application = applications_collection.find_one({
            '_id': ObjectId(application_id),
            'user_id': ObjectId(session['user_id'])
        })
        
        if not application:
            flash('Application not found or unauthorized access', 'error')
            return redirect(url_for('dashboard'))
        
        # Prepare data for template
        user_data = {
            'name': application['name'],
            'age': application['age'],
            'contact-number': application['contact_number'],
            'email': application['email'],
            'course': application['course'],
            'board-of-ed': application['board_of_education'],
            'secondary-school': application['secondary_school'],
            'secondary-roll': application['secondary_roll'],
            'senior-secondary-school': application['senior_secondary_school'],
            'father-name': application['father_name'],
            'father-occupation': application['father_occupation'],
            'mother-name': application['mother_name'],
            'exam-center-1': application['exam_center_1'],
            'exam-center-2': application['exam_center_2'],
            'exam-center-3':application['exam_center_3'],
        }
        
        return render_template('user.html', user=user_data)
    
    except Exception as e:
        flash('Error viewing application', 'error')
        return redirect(url_for('dashboard'))

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def login():
    if request.method == 'GET':
        email = request.form.get('email')
        password = request.form.get('password')

        # Query user by email
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            # Successful login
            session['user_id'] = user.id
            session['email'] = user.email
            return redirect(url_for('data'))
        else:
            # Invalid credentials
            error = "Invalid email or password"
            return render_template('login.html', error=error)

    return render_template('login.html')

@app.route('/data')
def data():
    # Ensure the user is logged in before accessing this page
    if 'user_id' in session:
        return render_template('data.html', email=session['email'])
    else:
        return redirect(url_for('login'))

hashed_password = bcrypt.generate_password_hash("test123").decode('utf-8')
new_user = User(email="test@example.com", password=hashed_password)
db.session.add(new_user)
db.session.commit()


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET'])  # Allow both GET and POST methods
def login():
    if request.method == 'GET':
        email = request.form.get('email')
        password = request.form.get('password')

        # Simulate user validation (replace with database query in production)
        if email == "test@example.com" and password == "password123":
            return redirect(url_for('data'))
        else:
            error = "Invalid email or password"
            return render_template('login.html', error=error)

    return render_template('login.html')  # Render login page for GET requests

@app.route('/data')
def data():
    return render_template('data.html')  # Welcome page after successful login

if __name__ == '__main__':
    app.run(debug=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)

@app.route("/signup", methods=["GET"])
def signup():
    if request.method == "GET":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmPassword")

        # Server-side validation
        if not all([username, email, password, confirm_password]):
            flash("All fields are required!", "error")
            return redirect(url_for("signup"))

        if not is_valid_email(email):
            flash("Invalid email format!", "error")
            return redirect(url_for("signup"))

        if not is_valid_password(password):
            flash("Password must be at least 8 characters long and include both letters and numbers!", "error")
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for("signup"))

        if users_collection.find_one({"email": email}):
            flash("Email already registered!", "error")
            return redirect(url_for("signup"))

        # If all validations pass, proceed with user creation
        hashed_password = generate_password_hash(password)
        user_data = {
            "username": username,
            "email": email,
            "password": hashed_password,
        }
        users_collection.insert_one(user_data)

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")
def login_required(f):
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET'])
def register():
    if request.method == 'GET':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm-password')

        if not all([username, email, password, confirm_password]):
            flash('All fields are required!', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))
        
        if users_collection.find_one({'email': email}):
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        user = {
            'username': username,
            'email': email,
            'password': hashed_password,
            'created_at': datetime.utcnow()
        }
        user_id = users_collection.insert_one(user).inserted_id

        session['user_id'] = str(user_id)
        flash('Registration successful!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET'])
def login():
    if request.method == 'GET':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = users_collection.find_one({'email': email})
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            flash('Login successful!', 'success')
            return redirect(url_for('user'))
        
        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/user')
@login_required
def user():
    try:
        user_data = users_collection.find_one({'_id': ObjectId(session['user_id'])})
        
        if not user_data:
            flash("User data not found!", "error")
            return redirect(url_for("dashboard"))

        # Pass user data to the template
        return render_template("user.html", user=user_data)
    
    except Exception as e:
        flash("Error retrieving user data", "error")
        return redirect(url_for("dashboard"))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/login', methods=['GET'])
def login():
    if request.method == 'GET':
        username = request.args.get('username')
        password = request.args.get('password')
        
        user = users_collection.find_one({'username': username})
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            # Get the latest application data for this user
            application = applications_collection.find_one(
                {'user_id': ObjectId(session['user_id'])},
                sort=[('created_at', -1)]
            )
            if application:
                session['application_data'] = str(application['_id'])
            return redirect(url_for('user'))
        
        flash('Invalid username or password', 'error')
        return redirect(url_for('login'))

@app.route('/user')
def user():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_data = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    
    application_data = None
    if 'application_data' in session:
        application_data = applications_collection.find_one(
            {'_id': ObjectId(session['application_data'])}
        )
    
    return render_template('user1.html', user=user_data, application=application_data)

@app.route('/get_application_data')
@login_required
def get_application_data():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401

        application = applications_collection.find_one({
            'user_id': ObjectId(session['user_id'])
        }, {'_id': 0})  # Exclude MongoDB _id field

        if not application:
            return jsonify({'error': 'No application found'}), 404

        # Convert ObjectId and other non-JSON serializable fields
        application['_id'] = str(application['_id']) if '_id' in application else None
        application['user_id'] = str(application['user_id']) if 'user_id' in application else None
        application['created_at'] = application['created_at'].isoformat() if 'created_at' in application else None

        return jsonify(application)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/application')
@login_required
def get_user_application():
    try:
        # Get current user's email from session
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Not authenticated'}), 401
        
        # Find user to get email
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Find latest application for this user
        application = applications_collection.find_one(
            {'user_id': ObjectId(user_id)},
            sort=[('created_at', -1)]  # Get most recent application
        )
        
        if not application:
            return jsonify({'error': 'No application found'}), 404
        
        # Convert ObjectId and datetime to strings
        application['_id'] = str(application['_id'])
        application['user_id'] = str(application['user_id'])
        if 'created_at' in application:
            application['created_at'] = application['created_at'].isoformat()
        
        return jsonify(application)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/login-handler', methods=['GET'])
def login_handler():
    email = request.args.get('email')
    password = request.args.get('password')
    
    # Validate credentials (in a real app, check against database)
    if email == "test@example.com" and password == "password123":
        return redirect(url_for('user_page', email=email))
    else:
        return redirect(url_for('login_page', error="Invalid credentials"))

@app.route('/user')
def user_page():
    email = request.args.get('email')
    # Fetch user data from database based on email
    # Render user1.html with the data
    return "User page for " + email  # In real app, render_template('user1.html', ...)

@app.route('/')
def login_page():
    error = request.args.get('error')
    # Render login.html with error if present
    return "Login page"  # In real app, render_template('login.html', error=error)

@app.route("/get_application_data")
def get_application_data():
    try:
        # Your code to fetch and process data
        data = ...
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 # 500 is Internal Server Error

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    full_name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    contact_number = db.Column(db.String(20))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Application Data Model
class ApplicationData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Add other application-specific fields here
    data_field1 = db.Column(db.String(100))
    data_field2 = db.Column(db.String(100))
    # ...

# Create tables (run once)
with app.app_context():
    db.create_all()

# Decorator to check if user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Session expired or invalid', 'redirect': '/login'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def home():
    if 'user_id' in session:
        return redirect(url_for('user_profile'))
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', session_expired=request.args.get('expired'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return render_template('login.html', error='Invalid username or password')
    
    session.permanent = True
    session['user_id'] = user.id
    session['username'] = user.username
    return redirect(url_for('user_profile'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/user")
def user_profile():
    if 'user_id' not in session:
        return redirect(url_for('login', expired = 'true'))
    return render_template('user1.html')

@app.route("/get_application_data")
@login_required
def get_application_data():
    try:
        user = User.query.get(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Fetch application data from database
        app_data = ApplicationData.query.filter_by(user_id=user.id).first()
        
        data = {
            'fullName': user.full_name,
            'age': user.age,
            'contactNumber': user.contact_number,
            'email': user.email,
            # Add application-specific data
            'data1': app_data.data_field1 if app_data else None,
            'data2': app_data.data_field2 if app_data else None
        }
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/check-session")
def check_session():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            return jsonify({
                'valid': True,
                'user_id': session['user_id'],
                'username': user.username
            })
    return jsonify({'valid': False}), 401

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login form submission
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check if user exists and password matches
        if username in users and users[username]['password'] == password:
            # Successful login - redirect to user page
            return redirect(url_for('user_page', username=username))
        else:
            # Failed login - show error
            return render_template('login.html', error="Invalid username or password")
    
    # GET request - show login form
    return render_template('login.html')

@app.route('/user1.html')
def user_page():
    username = request.args.get('username')
    if username in users:
        return f"Welcome, {users[username]['name']}!"
    return redirect(url_for('login'))

@app.route('/handleLogin', methods=['POST'])
def handle_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # Check credentials
    if username in users and users[username]['password'] == password:
        return jsonify({'success': True, 'redirect': url_for('user_page', username=username)})
    else:
        return jsonify({'success': False, 'message': 'Invalid username or password'})

if __name__ == '__main__':
    app.run(debug=True)

app = Flask(__name__)
DATABASE = 'users.db'

# Initialize database
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                         (username, hash_password(password)))
            user = cursor.fetchone()
        
        if user:
            return redirect(url_for('user_page', username=username))
        else:
            return render_template('login.html', error="Invalid username or password")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirmPassword']
        
        # Basic validation
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'})
        
        if len(password) < 8 or not any(char.isdigit() for char in password):
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters with at least one number'})
        
        try:
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                             (username, email, hash_password(password)))
                conn.commit()
            
            return jsonify({'success': True, 'redirect': url_for('login')})
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                return jsonify({'success': False, 'message': 'Username already exists'})
            elif 'email' in str(e):
                return jsonify({'success': False, 'message': 'Email already exists'})
    
    return render_template('signup.html')

@app.route('/handleSignup', methods=['POST'])
def handle_signup():
    data = request.get_json()
    return signup()  # Reuse the same logic

@app.route('/user1.html')
def user_page():
    username = request.args.get('username')
    return f"Welcome, {username}!"

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

app = Flask(__name__)
DATABASE = 'users.db'

# Initialize database with error handling
def init_db():
    try:
        # Create the database directory if it doesn't exist
        os.makedirs('instance', exist_ok=True)
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            # Check if table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            table_exists = cursor.fetchone()
            
            if not table_exists:
                cursor.execute('''
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                # Add a test user for demonstration
                cursor.execute('''
                    INSERT INTO users (username, email, password)
                    VALUES (?, ?, ?)
                ''', ('testuser', 'test@example.com', hash_password('test123')))
                conn.commit()
                print("Database and table created successfully with test user")
            else:
                print("Database already exists")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")
        raise

# Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.before_first_request
def before_first_request():
    init_db()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', 
                             (username, hash_password(password)))
                user = cursor.fetchone()
            
            if user:
                return redirect(url_for('user_page', username=username))
            else:
                return render_template('login.html', error="Invalid username or password")
        except sqlite3.Error as e:
            print(f"Database error: {str(e)}")
            return render_template('login.html', error="Database error occurred")
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        
        # Basic validation
        if not all([username, email, password, confirm_password]):
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'})
        
        if len(password) < 8 or not any(char.isdigit() for char in password):
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters with at least one number'})
        
        try:
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                             (username, email, hash_password(password)))
                conn.commit()
            
            return jsonify({'success': True, 'redirect': url_for('login')})
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                return jsonify({'success': False, 'message': 'Username already exists'})
            elif 'email' in str(e):
                return jsonify({'success': False, 'message': 'Email already exists'})
            else:
                return jsonify({'success': False, 'message': 'Database error occurred'})
        except Exception as e:
            print(f"Error during signup: {str(e)}")
            return jsonify({'success': False, 'message': 'An error occurred during signup'})

@app.route('/handleSignup', methods=['POST'])
def handle_signup():
    data = request.get_json()
    return signup()  # Reuse the same logic

@app.route('/user1.html')
def user_page():
    username = request.args.get('username')
    return f"Welcome, {username}!"

if __name__ == '__main__':
    # Ensure database is initialized before running
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Needed for session management
DATABASE = 'instance/users.db'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize database
def init_db():
    os.makedirs('instance', exist_ok=True)
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.before_first_request
def initialize():
    init_db()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
        
        if user and user[3] == hash_password(password):  # Check hashed password
            session['username'] = user[1]  # Store username in session
            session['email'] = user[2]     # Store email in session
            return jsonify({'success': True, 'redirect': url_for('user_page')})
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'})
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        
        # Validation
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'})
        
        try:
            hashed_pw = hash_password(password)
            with sqlite3.connect(DATABASE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, password)
                    VALUES (?, ?, ?)
                ''', (username, email, hashed_pw))
                conn.commit()
            
            return jsonify({'success': True, 'message': 'Registration successful!', 'redirect': url_for('login')})
        except sqlite3.IntegrityError as e:
            if 'email' in str(e):
                return jsonify({'success': False, 'message': 'Email already exists'})
            elif 'username' in str(e):
                return jsonify({'success': False, 'message': 'Username already exists'})
    
    return render_template('signup.html')

@app.route('/user')
@login_required
def user_page():
    return render_template('user.html', username=session['username'], email=session['email'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
