from flask_sqlalchemy import SQLAlchemy
import json
from datetime import datetime

# SQLAlchemy configuration (add this near your other configurations)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///applications.db'  # Using SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define your SQLAlchemy models
class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Personal Details
    name = db.Column(db.String(100))
    age = db.Column(db.Integer)
    contact_number = db.Column(db.String(20))
    email = db.Column(db.String(120))
    course = db.Column(db.String(100))
    government_id = db.Column(db.String(50))
    id_number = db.Column(db.String(50))
    pincode = db.Column(db.String(10))
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    address = db.Column(db.Text)
    
    # Education Details
    board_of_education = db.Column(db.String(100))
    secondary_school = db.Column(db.String(100))
    secondary_roll = db.Column(db.String(50))
    secondary_marks = db.Column(db.Float)
    senior_secondary_school = db.Column(db.String(100))
    senior_subjects = db.Column(db.String(200))
    senior_roll = db.Column(db.String(50))
    senior_marks = db.Column(db.Float)
    
    # Family Details
    father_name = db.Column(db.String(100))
    father_contact = db.Column(db.String(20))
    father_email = db.Column(db.String(120))
    father_occupation = db.Column(db.String(100))
    mother_name = db.Column(db.String(100))
    mother_contact = db.Column(db.String(20))
    mother_email = db.Column(db.String(120))
    mother_occupation = db.Column(db.String(100))
    annual_income = db.Column(db.Float)
    
    # Exam Centers
    exam_center_1 = db.Column(db.String(100))
    exam_center_2 = db.Column(db.String(100))
    exam_center_3 = db.Column(db.String(100))
    exam_center_4 = db.Column(db.String(100))
    exam_center_5 = db.Column(db.String(100))
    
    # Document Paths
    passport_photo = db.Column(db.String(200))
    signature = db.Column(db.String(200))
    marksheet_10th = db.Column(db.String(200))
    marksheet_12th = db.Column(db.String(200))
    id_proof = db.Column(db.String(200))

# Add this endpoint to get all data as JSON
@app.route('/api/applications/json')
@login_required
def get_applications_json():
    try:
        # Get all applications for the current user
        applications = Application.query.filter_by(user_id=session['user_id']).all()
        
        # Convert to dictionary
        applications_list = []
        for app in applications:
            app_dict = {
                'id': app.id,
                'user_id': app.user_id,
                'created_at': app.created_at.isoformat() if app.created_at else None,
                
                # Personal Details
                'name': app.name,
                'age': app.age,
                'contact_number': app.contact_number,
                'email': app.email,
                'course': app.course,
                'government_id': app.government_id,
                'id_number': app.id_number,
                'pincode': app.pincode,
                'city': app.city,
                'state': app.state,
                'address': app.address,
                
                # Education Details
                'board_of_education': app.board_of_education,
                'secondary_school': app.secondary_school,
                'secondary_roll': app.secondary_roll,
                'secondary_marks': app.secondary_marks,
                'senior_secondary_school': app.senior_secondary_school,
                'senior_subjects': app.senior_subjects,
                'senior_roll': app.senior_roll,
                'senior_marks': app.senior_marks,
                
                # Family Details
                'father_name': app.father_name,
                'father_contact': app.father_contact,
                'father_email': app.father_email,
                'father_occupation': app.father_occupation,
                'mother_name': app.mother_name,
                'mother_contact': app.mother_contact,
                'mother_email': app.mother_email,
                'mother_occupation': app.mother_occupation,
                'annual_income': app.annual_income,
                
                # Exam Centers
                'exam_center_1': app.exam_center_1,
                'exam_center_2': app.exam_center_2,
                'exam_center_3': app.exam_center_3,
                'exam_center_4': app.exam_center_4,
                'exam_center_5': app.exam_center_5,
                
                # Document Paths
                'passport_photo': app.passport_photo,
                'signature': app.signature,
                'marksheet_10th': app.marksheet_10th,
                'marksheet_12th': app.marksheet_12th,
                'id_proof': app.id_proof
            }
            applications_list.append(app_dict)
        
        # Save to JSON file
        with open('applications.json', 'w') as f:
            json.dump(applications_list, f, indent=4)
        
        return jsonify({
            'success': True,
            'applications': applications_list,
            'message': 'Data exported to applications.json'
        })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Update your submit_form endpoint to save to SQL as well
@app.route('/submit', methods=['POST'])
@login_required
def submit_form():
    try:
        # Handle file uploads (same as before)
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

        # Create and save SQL application
        application = Application(
            user_id=session['user_id'],
            
            # Personal Details
            name=request.form.get('name'),
            age=int(request.form.get('age')),
            contact_number=request.form.get('contact-number'),
            email=request.form.get('email'),
            course=request.form.get('course'),
            government_id=request.form.get('government-id'),
            id_number=request.form.get('id-number'),
            pincode=request.form.get('pincode'),
            city=request.form.get('city'),
            state=request.form.get('state'),
            address=request.form.get('address'),
            
            # Education Details
            board_of_education=request.form.get('board-of-ed'),
            secondary_school=request.form.get('secondary-school'),
            secondary_roll=request.form.get('secondary-roll'),
            secondary_marks=float(request.form.get('secondary-marks')),
            senior_secondary_school=request.form.get('senior-secondary-school'),
            senior_subjects=request.form.get('senior-subjects'),
            senior_roll=request.form.get('senior-roll'),
            senior_marks=float(request.form.get('senior-marks')),
            
            # Family Details
            father_name=request.form.get('father-name'),
            father_contact=request.form.get('father-contact'),
            father_email=request.form.get('father-email'),
            father_occupation=request.form.get('father-occupation'),
            mother_name=request.form.get('mother-name'),
            mother_contact=request.form.get('mother-contact'),
            mother_email=request.form.get('mother-email'),
            mother_occupation=request.form.get('mother-occupation'),
            annual_income=float(request.form.get('annual-income')),
            
            # Exam Centers
            exam_center_1=request.form.get('exam-center-1'),
            exam_center_2=request.form.get('exam-center-2'),
            exam_center_3=request.form.get('exam-center-3'),
            exam_center_4=request.form.get('exam-center-4'),
            exam_center_5=request.form.get('exam-center-5'),
            
            # Document Paths
            **file_paths
        )
        
        db.session.add(application)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Application submitted successfully!',
            'application_id': application.id
        })
    
    except ValueError as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
