from flask import Flask, jsonify, request, render_template
import psycopg2
from flask_bcrypt import Bcrypt
import jwt
import datetime
import logging
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for cross-origin requests

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    filename='app.log',
    filemode='w',
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
logger.addHandler(console_handler)

# Database configuration
DB_HOST = 'localhost'
DB_NAME = 'postgres'
DB_USER = 'postgres'
DB_PASSWORD = '1616'  # Update this to match your PostgreSQL password
SECRET_KEY = "this is a secret key this is a secret keyyyy!!!!"

AVAILABLE_COURSES = ['Python', 'AI', 'C', 'Java', 'HTML', 'CSS']

def get_db_connection():
    try:
        connection = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        logger.debug("Database connection acquired")
        return connection
    except Exception as e:
        logger.error(f"Error getting database connection: {str(e)}")
        raise

def init_db():
    logger.info("Initializing database tables...")
    connection = get_db_connection()
    try:
        cursor = connection.cursor()

        # Drop existing tables to avoid conflicts (for testing)
        cursor.execute("DROP TABLE IF EXISTS created_exam_users CASCADE;")
        cursor.execute("DROP TABLE IF EXISTS exam_results CASCADE;")
        cursor.execute("DROP TABLE IF EXISTS attendance CASCADE;")
        cursor.execute("DROP TABLE IF EXISTS attendance_requests CASCADE;")
        cursor.execute("DROP TABLE IF EXISTS exam_answers CASCADE;")
        cursor.execute("DROP TABLE IF EXISTS exam_questions CASCADE;")
        cursor.execute("DROP TABLE IF EXISTS videos CASCADE;")
        cursor.execute("DROP TABLE IF EXISTS exam_users CASCADE;")
        cursor.execute("DROP TABLE IF EXISTS students CASCADE;")

        # Students table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                college_roll_number TEXT NOT NULL UNIQUE,
                college_name TEXT NOT NULL,
                password TEXT NOT NULL,
                group_name TEXT,
                selected_course TEXT,
                is_admin BOOLEAN DEFAULT FALSE
            );
        """)

        # Exam Users table (temporary storage)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exam_users (
                id SERIAL PRIMARY KEY,
                exam_user_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                exam_start_time TIMESTAMP
            );
        """)

        # Created Exam Users table (persistent storage for exam user details)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS created_exam_users (
                id SERIAL PRIMARY KEY,
                exam_user_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Exam Results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exam_results (
                result_id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                score INTEGER NOT NULL,
                total_questions INTEGER NOT NULL,
                submission_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS videos (
                video_id SERIAL PRIMARY KEY,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                explanation TEXT NOT NULL,
                sequence INTEGER NOT NULL
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exam_questions (
                question_id SERIAL PRIMARY KEY,
                question TEXT NOT NULL,
                option_a TEXT NOT NULL,
                option_b TEXT NOT NULL,
                option_c TEXT NOT NULL,
                option_d TEXT NOT NULL,
                correct_answer TEXT NOT NULL,
                subject TEXT NOT NULL
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exam_answers (
                answer_id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES exam_users(id) ON DELETE CASCADE,
                question_id INTEGER REFERENCES exam_questions(question_id),
                submitted_answer TEXT NOT NULL,
                submission_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attendance_requests (
                request_id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
                group_name TEXT NOT NULL,
                request_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected'))
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                attendance_id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES students(id) ON DELETE CASCADE,
                group_name TEXT NOT NULL,
                attendance_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Insert sample video data
        cursor.execute("""
            INSERT INTO videos (category, title, url, explanation, sequence) VALUES
            ('Python', 'Python Basics', 'https://www.youtube.com/embed/YYXdXT2l-Gg', 'Introduction to Python.', 1),
            ('Python', 'Variables', 'https://www.youtube.com/embed/8DvywoWv6fI', 'Learn variables in Python.', 2),
            ('Python', 'Loops', 'https://www.youtube.com/embed/kWiCuklohdY', 'Understand loops in Python.', 3),
            ('AI', 'AI Basics', 'https://www.youtube.com/embed/5q87K1WaoFI', 'Introduction to AI.', 1),
            ('C', 'C Basics', 'https://www.youtube.com/embed/KJgsSFOSQv0', 'Introduction to C.', 1),
            ('Java', 'Java Basics', 'https://www.youtube.com/embed/W6NZfCO5SIk', 'Introduction to Java.', 1),
            ('HTML', 'HTML Basics', 'https://www.youtube.com/embed/UB1O30fR-EE', 'Introduction to HTML.', 1),
            ('CSS', 'CSS Basics', 'https://www.youtube.com/embed/yfoY53QXEnI', 'Introduction to CSS.', 1)
            ON CONFLICT DO NOTHING;
        """)

        # Ensure admin user (id=1)
        admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        cursor.execute("""
            INSERT INTO students (id, email, college_roll_number, college_name, password, username, group_name, selected_course, is_admin)
            VALUES (1, 'admin@example.com', 'ADMIN001', 'Admin College', %s, 'admin', 'Admin Group', 'Python', TRUE)
            ON CONFLICT (id) DO UPDATE SET
                email = EXCLUDED.email,
                college_roll_number = EXCLUDED.college_roll_number,
                college_name = EXCLUDED.college_name,
                password = EXCLUDED.password,
                username = EXCLUDED.username,
                group_name = EXCLUDED.group_name,
                selected_course = EXCLUDED.selected_course,
                is_admin = EXCLUDED.is_admin
            RETURNING id;
        """, (admin_password,))
        admin_id = cursor.fetchone()[0]
        logger.info(f"Admin user ensured: id={admin_id}, email=admin@example.com")

        # Reset sequence for students
        cursor.execute("""
            SELECT setval('students_id_seq', (SELECT COALESCE(MAX(id), 1) FROM students));
        """)
        logger.info("Students sequence reset to match max id")

        # Insert sample exam questions
        sample_questions = [
            ("What is 2+2?", "2", "3", "4", "5", "C", "Math"),
            ("What is Python?", "A snake", "A programming language", "A food", "A country", "B", "Programming"),
            ("What is the capital of France?", "Florida", "Paris", "Texas", "London", "B", "Geography"),
            ("What is 5*5?", "20", "25", "30", "35", "B", "Math"),
            ("Which is a fruit?", "Carrot", "Apple", "Potato", "Broccoli", "B", "Biology"),
        ] + [("Sample Question " + str(i), "A", "B", "C", "D", "A", "General") for i in range(15)]
        for q in sample_questions:
            cursor.execute("""
                INSERT INTO exam_questions (question, option_a, option_b, option_c, option_d, correct_answer, subject)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING;
            """, q)

        # Insert sample regular user
        cursor.execute("""
            INSERT INTO students (email, college_roll_number, college_name, password, username, group_name, selected_course)
            VALUES ('praveenstar977@gmail.com', 'ROLL001', 'Sample College', %s, 'praveen', 'Group A', 'Python')
            ON CONFLICT (email) DO NOTHING;
        """, (bcrypt.generate_password_hash('praveen123').decode('utf-8'),))

        connection.commit()
        logger.info("Database tables and sample data initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise
    finally:
        cursor.close()
        connection.close()

bcrypt = Bcrypt(app)

def encode_token(user_id, email, is_admin=False, is_exam_user=False):
    try:
        token = jwt.encode({
            'user_id': user_id,
            'email': email,
            'is_admin': is_admin,
            'is_exam_user': is_exam_user,
            'exp': datetime.datetime.utcnow() + (datetime.timedelta(minutes=20) if is_exam_user else datetime.timedelta(hours=24))
        }, SECRET_KEY, algorithm='HS256')
        logger.debug(f"Token generated: user_id={user_id}, is_admin={is_admin}, is_exam_user={is_exam_user}")
        return token
    except Exception as e:
        logger.error(f"Error encoding token: {str(e)}")
        raise

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        logger.debug(f"Token verified: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.error("Token expired")
        return None
    except jwt.InvalidTokenError:
        logger.error("Invalid token")
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            logger.warning("No token provided")
            return jsonify({'message': 'Token is missing'}), 401
        payload = verify_token(token)
        if not payload:
            return jsonify({'message': 'Invalid or expired token'}), 401
        request.user = payload
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if not request.user.get('is_admin'):
            logger.warning(f"Non-admin access attempt: {request.user}")
            return jsonify({'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

# Regular User Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    required_fields = ['email', 'password', 'username', 'group_name', 'selected_course', 'college_roll_number', 'college_name']
    if not data or not all(k in data for k in required_fields):
        logger.warning("Invalid registration data")
        return jsonify({'message': 'Missing required fields'}), 400
    
    email = data['email']
    password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    username = data['username']
    group_name = data['group_name']
    college_roll_number = data['college_roll_number']
    college_name = data['college_name']
    selected_course = data['selected_course'] if data['selected_course'] in AVAILABLE_COURSES else None
    
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO students (email, college_roll_number, college_name, password, username, group_name, selected_course)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (email, college_roll_number, college_name, password, username, group_name, selected_course))
        user_id = cursor.fetchone()[0]
        token = encode_token(user_id, email)
        connection.commit()
        logger.info(f"User registered: {email}, group_name={group_name}, selected_course={selected_course}")
        return jsonify({'token': token, 'message': 'Registration successful'}), 201
    except psycopg2.IntegrityError as e:
        logger.warning(f"Email, username, or roll number already exists: {email}, Error: {str(e)}")
        return jsonify({'message': 'Email, username, or college roll number already exists'}), 400
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not all(k in data for k in ('email', 'password')):
        logger.warning("Invalid login data")
        return jsonify({'message': 'Missing required fields'}), 400
    
    email = data['email']
    password = data['password']
    
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT id, email, password, is_admin FROM students WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            logger.warning(f"User not found: {email}")
            return jsonify({'message': 'User not found'}), 401
        if bcrypt.check_password_hash(user[2], password):
            token = encode_token(user[0], user[1], user[3])
            logger.info(f"Login successful: {email}, is_admin: {user[3]}")
            return jsonify({'token': token, 'message': 'Login successful'}), 200
        logger.warning(f"Password incorrect for: {email}")
        return jsonify({'message': 'Incorrect password'}), 401
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/categories', methods=['GET'])
@token_required
def get_categories():
    if request.user.get('is_exam_user'):
        return jsonify({'message': 'Exam users cannot access courses'}), 403
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT selected_course FROM students WHERE id = %s", (request.user['user_id'],))
        selected_course = cursor.fetchone()[0]
        return jsonify({
            'categories': AVAILABLE_COURSES,
            'selected_course': selected_course
        }), 200
    except Exception as e:
        logger.error(f"Error fetching categories: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/select_course', methods=['POST'])
@token_required
def select_course():
    if request.user.get('is_exam_user'):
        return jsonify({'message': 'Exam users cannot select courses'}), 403
    data = request.get_json()
    if not data or 'course' not in data:
        logger.warning("Invalid course selection data")
        return jsonify({'message': 'Missing course field'}), 400
    
    course = data['course']
    if course not in AVAILABLE_COURSES:
        logger.warning(f"Invalid course selected: {course}")
        return jsonify({'message': 'Invalid course'}), 400
    
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("UPDATE students SET selected_course = %s WHERE id = %s", (course, request.user['user_id']))
        connection.commit()
        logger.info(f"Course selected: user_id={request.user['user_id']}, course={course}")
        return jsonify({'message': f'Course {course} unlocked successfully'}), 200
    except Exception as e:
        logger.error(f"Error selecting course: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/learning/<category>', methods=['GET'])
@token_required
def learning(category):
    if request.user.get('is_exam_user'):
        return jsonify({'message': 'Exam users cannot access learning content'}), 403
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT selected_course FROM students WHERE id = %s", (request.user['user_id'],))
        selected_course = cursor.fetchone()[0]
        
        if not request.user.get('is_admin') and (selected_course is None or selected_course != category):
            logger.warning(f"Course not unlocked: user_id={request.user['user_id']}, category={category}")
            return jsonify({'message': 'Course not unlocked. Please select this course first.'}), 403
        
        cursor.execute("SELECT video_id, title, url, explanation, sequence FROM videos WHERE category = %s ORDER BY sequence", 
                       (category,))
        videos = cursor.fetchall()
        return jsonify({
            'videos': [{'id': v[0], 'title': v[1], 'url': v[2], 'explanation': v[3], 'sequence': v[4]} for v in videos]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching videos for category {category}: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

# Exam Routes
@app.route('/admin/create_exam_user', methods=['POST'])
@admin_required
def create_exam_user():
    data = request.get_json()
    if not data or not all(k in data for k in ['exam_user_id', 'name', 'username', 'email', 'password']):
        logger.warning("Invalid request data for creating exam user")
        return jsonify({'message': 'Missing required fields'}), 400

    exam_user_id = data['exam_user_id']
    name = data['name']
    username = data['username']
    email = data['email']
    password = data['password']

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        # Insert into exam_users (temporary table)
        cursor.execute("""
            INSERT INTO exam_users (exam_user_id, name, username, email, password)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (exam_user_id, name, username, email, hashed_password))
        user_id = cursor.fetchone()[0]

        # Insert into created_exam_users (persistent table)
        cursor.execute("""
            INSERT INTO created_exam_users (exam_user_id, name, username, email)
            VALUES (%s, %s, %s, %s)
        """, (exam_user_id, name, username, email))

        connection.commit()
        logger.info(f"Exam user created: exam_user_id={exam_user_id}, username={username}, email={email}, user_id={user_id}")
        return jsonify({
            'message': 'Exam user created successfully',
            'exam_user_id': exam_user_id,
            'name': name,
            'username': username,
            'email': email
        }), 201
    except psycopg2.IntegrityError as e:
        logger.error(f"Integrity error creating exam user: {str(e)}")
        return jsonify({'message': 'Exam User ID, username, or email already exists'}), 400
    except Exception as e:
        logger.error(f"Error creating exam user: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/admin/exam_users', methods=['GET'])
@admin_required
def get_exam_users():
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT id, exam_user_id, name, username, email, created_at
            FROM created_exam_users
            ORDER BY created_at DESC
        """)
        exam_users = cursor.fetchall()
        return jsonify({
            'exam_users': [{
                'id': u[0],
                'exam_user_id': u[1],
                'name': u[2],
                'username': u[3],
                'email': u[4],
                'created_at': u[5].isoformat()
            } for u in exam_users]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching exam users: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/exam/login', methods=['POST'])
def exam_login():
    data = request.get_json()
    if not data or not all(k in data for k in ['exam_user_id', 'password']):
        logger.warning("Missing exam_user_id or password")
        return jsonify({'message': 'Missing exam_user_id or password'}), 400

    exam_user_id = data['exam_user_id']
    password = data['password']
    
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT id, email, password 
            FROM exam_users 
            WHERE exam_user_id = %s
        """, (exam_user_id,))
        user = cursor.fetchone()
        if not user:
            logger.warning(f"Invalid exam user ID: {exam_user_id}")
            return jsonify({'message': 'Invalid exam user ID'}), 401
        if not bcrypt.check_password_hash(user[2], password):
            logger.warning(f"Incorrect password for exam user ID: {exam_user_id}")
            return jsonify({'message': 'Incorrect password'}), 401
        
        token = encode_token(user[0], user[1], is_exam_user=True)
        cursor.execute("UPDATE exam_users SET exam_start_time = %s WHERE id = %s", 
                       (datetime.datetime.now(), user[0]))
        connection.commit()
        logger.info(f"Exam login successful: exam_user_id={exam_user_id}")
        return jsonify({'token': token, 'message': 'Exam login successful'}), 200
    except Exception as e:
        logger.error(f"Exam login error: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/exam/questions', methods=['GET'])
@token_required
def get_exam_questions():
    if not request.user.get('is_exam_user'):
        logger.warning("Non-exam user attempted to access exam questions")
        return jsonify({'message': 'Not an exam user'}), 403
    
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT question_id, question, option_a, option_b, option_c, option_d FROM exam_questions LIMIT 20")
        questions = cursor.fetchall()
        return jsonify([{
            'question_id': q[0],
            'question': q[1],
            'options': [q[2], q[3], q[4], q[5]]
        } for q in questions]), 200
    except Exception as e:
        logger.error(f"Error fetching exam questions: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/exam/submit', methods=['POST'])
@token_required
def submit_exam():
    if not request.user.get('is_exam_user'):
        logger.warning("Non-exam user attempted to submit exam")
        return jsonify({'message': 'Not an exam user'}), 403
    
    answers = request.get_json().get('answers')
    if not answers:
        logger.warning("No answers provided for exam submission")
        return jsonify({'message': 'No answers provided'}), 400

    user_id = request.user['user_id']
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        
        # Check time limit
        cursor.execute("SELECT exam_start_time, name, email FROM exam_users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        if not result:
            logger.warning(f"Exam user not found: user_id={user_id}")
            return jsonify({'message': 'User not found'}), 404
        start_time, name, email = result
        if (datetime.datetime.now() - start_time).total_seconds() > 1200:  # 20 minutes
            cursor.execute("DELETE FROM exam_users WHERE id = %s", (user_id,))
            connection.commit()
            logger.warning(f"Time limit exceeded for user_id={user_id}")
            return jsonify({'message': 'Time limit exceeded'}), 400
        
        # Submit answers and calculate score
        score = 0
        for answer in answers:
            cursor.execute("""
                INSERT INTO exam_answers (user_id, question_id, submitted_answer)
                VALUES (%s, %s, %s)
            """, (user_id, answer['question_id'], answer['answer']))
            
            cursor.execute("SELECT correct_answer FROM exam_questions WHERE question_id = %s", (answer['question_id'],))
            correct = cursor.fetchone()
            if correct and answer['answer'].lower() == correct[0].lower():
                score += 1
        
        # Store exam results in exam_results table
        cursor.execute("""
            INSERT INTO exam_results (name, email, score, total_questions)
            VALUES (%s, %s, %s, %s)
        """, (name, email, score, len(answers)))
        
        # Delete exam user from temporary table
        cursor.execute("DELETE FROM exam_users WHERE id = %s", (user_id,))
        connection.commit()
        
        logger.info(f"Exam submitted: user_id={user_id}, score={score}")
        return jsonify({
            'message': 'Exam submitted successfully',
            'score': score,
            'total': len(answers)
        }), 200
    except Exception as e:
        logger.error(f"Error submitting exam: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

# Admin Routes
@app.route('/admin/users', methods=['GET'])
@admin_required
def get_registered_users():
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT id, username, email, college_roll_number, college_name, group_name, selected_course
            FROM students
            WHERE is_admin = FALSE
        """)
        users = cursor.fetchall()
        return jsonify({
            'users': [{
                'id': u[0],
                'username': u[1],
                'email': u[2],
                'college_roll_number': u[3],
                'college_name': u[4],
                'group_name': u[5],
                'selected_course': u[6]
            } for u in users]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching registered users: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/admin/exam_results', methods=['GET'])
@admin_required
def get_exam_results():
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT result_id, name, email, score, total_questions, submission_time
            FROM exam_results
            ORDER BY submission_time DESC
        """)
        results = cursor.fetchall()
        return jsonify({
            'results': [{
                'result_id': r[0],
                'name': r[1],
                'email': r[2],
                'score': r[3],
                'total_questions': r[4],
                'submission_time': r[5].isoformat()
            } for r in results]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching exam results: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

# Attendance Routes
@app.route('/attendance/request', methods=['POST'])
@token_required
def request_attendance():
    if request.user.get('is_exam_user'):
        return jsonify({'message': 'Exam users cannot request attendance'}), 403
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT group_name FROM students WHERE id = %s", (request.user['user_id'],))
        group_name = cursor.fetchone()[0]
        cursor.execute("INSERT INTO attendance_requests (user_id, group_name) VALUES (%s, %s) RETURNING request_id", 
                       (request.user['user_id'], group_name))
        request_id = cursor.fetchone()[0]
        connection.commit()
        logger.info(f"Attendance request created: user_id={request.user['user_id']}, group_name={group_name}, request_id={request_id}")
        return jsonify({'message': 'Attendance request submitted', 'request_id': request_id}), 201
    except Exception as e:
        logger.error(f"Error requesting attendance: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/attendance/admin', methods=['GET', 'POST'])
@admin_required
def admin_attendance():
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        if request.method == 'GET':
            cursor.execute("""
                SELECT ar.request_id, u.id, u.username, ar.group_name, ar.request_date, ar.status 
                FROM attendance_requests ar 
                JOIN students u ON ar.user_id = u.id 
                WHERE ar.status = 'pending'
            """)
            requests = cursor.fetchall()
            return jsonify({
                'requests': [{'request_id': r[0], 'user_id': r[1], 'username': r[2], 'group_name': r[3], 
                            'request_date': r[4].isoformat(), 'status': r[5]} for r in requests]
            }), 200
        
        if request.method == 'POST':
            data = request.get_json()
            if not data or 'request_id' not in data or 'action' not in data:
                logger.warning("Invalid admin attendance data")
                return jsonify({'message': 'Missing required fields'}), 400
            
            request_id = data['request_id']
            action = data['action']
            
            cursor.execute("SELECT user_id, group_name FROM attendance_requests WHERE request_id = %s AND status = 'pending'", 
                           (request_id,))
            result = cursor.fetchone()
            if not result:
                logger.warning(f"Request not found or already processed: {request_id}")
                return jsonify({'message': 'Request not found or already processed'}), 404
            
            user_id, group_name = result
            if action == 'accept':
                cursor.execute("UPDATE attendance_requests SET status = 'accepted' WHERE request_id = %s", (request_id,))
                cursor.execute("INSERT INTO attendance (user_id, group_name) VALUES (%s, %s)", (user_id, group_name))
                connection.commit()
                logger.info(f"Attendance accepted: request_id={request_id}, group_name={group_name}")
                return jsonify({'message': 'Attendance accepted'}), 200
            elif action == 'reject':
                cursor.execute("UPDATE attendance_requests SET status = 'rejected' WHERE request_id = %s", (request_id,))
                connection.commit()
                logger.info(f"Attendance rejected: request_id={request_id}, group_name={group_name}")
                return jsonify({'message': 'Attendance rejected'}), 200
            logger.warning(f"Invalid action: {action}")
            return jsonify({'message': 'Invalid action'}), 400
    except Exception as e:
        logger.error(f"Error in admin attendance: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/attendance', methods=['GET'])
@token_required
def get_attendance():
    if request.user.get('is_exam_user'):
        return jsonify({'message': 'Exam users cannot view attendance'}), 403
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        if request.user.get('is_admin'):
            cursor.execute("""
                SELECT a.attendance_id, u.username, u.group_name, a.attendance_date 
                FROM attendance a 
                JOIN students u ON a.user_id = u.id
            """)
        else:
            cursor.execute("""
                SELECT a.attendance_id, a.attendance_date 
                FROM attendance a
                WHERE a.user_id = %s
            """, (request.user['user_id'],))
        attendance = cursor.fetchall()
        if request.user.get('is_admin'):
            return jsonify({
                'attendance': [{'attendance_id': a[0], 'username': a[1], 'group_name': a[2], 'date': a[3].isoformat()} 
                              for a in attendance]
            }), 200
        else:
            return jsonify({
                'attendance': [{'attendance_id': a[0], 'date': a[1].isoformat()} for a in attendance]
            }), 200
    except Exception as e:
        logger.error(f"Error fetching attendance: {str(e)}")
        return jsonify({'message': 'Server error'}), 500
    finally:
        cursor.close()
        connection.close()

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    logger.info("Starting Flask application...")
    try:
        init_db()
        app.run(debug=True, host='0.0.0.0', port=5000)
        logger.info("Flask application started successfully")
    except Exception as e:
        logger.error(f"Startup error: {str(e)}")
        print(f"Failed to start application: {str(e)}")
        exit(1)