from flask import Flask, render_template, request, redirect, jsonify,session
import logging
# from pyzbar.pyzbar import decode
from PIL import Image
import requests
import mysql.connector
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "SPCLibrary"

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="librarymanagent", )

cursor = db.cursor()



# Route to the selection page
# Add this function at the top of your file with other imports
def get_book_description_from_api(isbn):
    try:
        url = f"https://www.googleapis.com/books/v1/volumes?q=isbn:{isbn}"
        response = requests.get(url)
        data = response.json()
        
        if 'items' in data and len(data['items']) > 0:
            volume_info = data['items'][0]['volumeInfo']
            return volume_info.get('description', 'No description available')
        return 'No description available'
    except Exception as e:
        logging.error(f"Error fetching description: {str(e)}")
        return 'No description available'
    
# Update check_session function to allow these routes
def check_session():
    """Check if user has valid session"""
    # Get current endpoint
    endpoint = request.endpoint
    
    # List of public routes that don't require authentication
    PUBLIC_ROUTES = {
        'static',
        'home_page',
        'login_page',
        'selection_page',
        'signup_page_student',
        'signup_page_faculty',
        'signup_page_staff',
        'info',
        'announcement',
        'librarian',
        'get_book_description',
        'get_book_details',
        'get-announcements'
    }
    
    # Allow access to public routes and static files
    if endpoint in PUBLIC_ROUTES or endpoint == 'static':
        return True
        
    # For protected routes, check authentication
    if endpoint not in PUBLIC_ROUTES:
        if not session.get('admin_id') and not session.get('student_id'):
            logging.warning(f'Unauthorized access attempt to: {endpoint}')
            return False
            
    return True

@app.before_request
def require_login():
    """Check every request before processing"""
    # Skip checking for static files
    if request.endpoint == 'static':
        return None
        
    # If not authenticated and trying to access protected route
    if not check_session():
        # Store attempted URL in session
        session['next'] = request.url
        return redirect('/login_page')

@app.route('/')
def home_page():
    try:
        # Fetch books data
        cursor.execute("SELECT ISBN, CoverImage, Title, Author, Genre FROM booktb")
        books_data = cursor.fetchall()
        
        books = []
        for book in books_data:
            books.append({
                'ISBN': book[0],
                'CoverImage': book[1],
                'Title': book[2],
                'Author': book[3],
                'Genre': book[4]
            })

        # Fetch and process genres
        cursor.execute("SELECT DISTINCT Genre FROM booktb WHERE Genre IS NOT NULL AND Genre != ''")
        genres_data = cursor.fetchall()
        
        # Create a set of unique genres
        unique_genres = set()
        for genre_data in genres_data:
            if genre_data[0]:  # Check if genre is not None
                # Split genres if they're comma-separated
                genres = genre_data[0].split(',')
                for genre in genres:
                    # Clean up the genre string
                    cleaned_genre = genre.strip()
                    if cleaned_genre:
                        unique_genres.add(cleaned_genre)
        
        # Sort genres alphabetically
        sorted_genres = sorted(list(unique_genres))
        
        logging.info('Home page data fetched successfully')
        return render_template('Home_Page.html', books=books, genres=sorted_genres)
    except Exception as e:
        logging.error(f'An error occurred: {str(e)}')
        return f"An error occurred: {str(e)}"

# Add this new route to fetch description
@app.route('/get_book_description/<isbn>')
def get_book_description(isbn):
    try:
        url = f"https://www.googleapis.com/books/v1/volumes?q=isbn:{isbn}"
        response = requests.get(url)
        data = response.json()
        
        if 'items' in data and len(data['items']) > 0:
            volume_info = data['items'][0]['volumeInfo']
            description = volume_info.get('description', 'No description available')
        else:
            description = 'No description available'
            
        return jsonify({'description': description})
    except Exception as e:
        return jsonify({'description': f'Error fetching description: {str(e)}'})
    
@app.route('/get_book_details/<isbn>')
def get_book_details(isbn):
    try:
        url = f'https://www.googleapis.com/books/v1/volumes?q=isbn:{isbn}'
        response = requests.get(url)
        data = response.json()

        if 'items' in data and len(data['items']) > 0:
            book_info = data['items'][0]['volumeInfo']
            
            details = {
                'description': book_info.get('description', 'No description available'),
                'publishedDate': book_info.get('publishedDate', 'Not available'),
                'language': book_info.get('language', 'Not available').upper(),
                'lcc': 'Not available',
                'publisher': book_info.get('publisher', 'Not available') # Added publisher
            }
            
            return jsonify(details)
        else:
            return jsonify({
                'description': 'No description available',
                'publishedDate': 'Not available',
                'language': 'Not available',
                'lcc': 'Not available',
                'publisher': 'Not available'
            })

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({
            'description': 'Error fetching book details',
            'publishedDate': 'Not available',
            'language': 'Not available',
            'lcc': 'Not available',
            'publisher': 'Not available'
        })

    
@app.route('/selection_page', methods=['GET','POST'])
def selection_page():
    if request.method == 'POST':
        user_type = request.form.get('user_type')
        if user_type == 'Student':
            return redirect('/signup_page_student')
        elif user_type == 'Faculty':
            return redirect('/signup_page_faculty')
        elif user_type == 'Staff':
            return redirect('/signup_page_staff')
    return render_template('Signup_Page_Student.html')

import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/signup_page_student', methods=['GET', 'POST'])
def signup_page_student():
    if request.method == 'POST':
        try:
            # Get form data with proper error handling
            id_number = request.form.get('ID_Number', '').strip()
            name = request.form.get('Name', '').strip()
            department = request.form.get('Department', '').strip()
            level = request.form.get('Level', '').strip()
            course_strand = request.form.get('Course_Strand', '').strip()
            email = request.form.get('Email', '').strip()
            gender = request.form.get('Gender', '').strip()

            # Validate required fields
            if not all([id_number, name, department, level, course_strand, email, gender]):
                return 'All fields are required', 400

            # Check if ID number already exists
            cursor.execute("SELECT ID_Number FROM clienttb WHERE ID_Number = %s", (id_number,))
            if cursor.fetchone():
                return 'ID Number already exists', 400

            # Insert data into the ClientTB table
            insert_query = """
                INSERT INTO clienttb 
                (ID_Number, Name, Department, Level, `Course/Strand`, Email, Gender) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (
                id_number,
                name,
                department,
                level,
                course_strand,
                email,
                gender
            ))
            db.commit()
            
            logging.info(f'Student {id_number} registered successfully')
            return redirect('/login_page')

        except mysql.connector.Error as db_error:
            db.rollback()
            logging.error(f'Database error during student signup: {str(db_error)}')
            return f'Database error: {str(db_error)}', 500
            
        except Exception as e:
            db.rollback()
            logging.error(f'Error during student signup: {str(e)}')
            return f'An error occurred: {str(e)}', 500

    # GET request - display the signup form
    return render_template('Signup_Page_Student.html')

# Add this function to check if user is authenticated
def is_authenticated():
    return 'admin_id' in session or 'student_id' in session

# Add this at the top of your file
def check_auth():
    """Check if user is authenticated and return their role"""
    if session.get('is_admin'):
        return 'admin'
    elif session.get('student_id'):
        return 'student'
    return None

@app.route('/admin_dashboard')
def dashboard():
    auth_status = check_auth()
    if not auth_status or auth_status != 'admin':
        logging.warning('Unauthorized access attempt to admin dashboard')
        return redirect('/login_page')
    
    try:
        # Fetch admin users data
        cursor.execute("""
            SELECT admin_id, name, email, role, is_active 
            FROM admin_users 
            ORDER BY admin_id
        """)
        admin_users = cursor.fetchall()
        
        # Convert to list of dictionaries for easier template handling
        admin_data = [{
            'id': admin[0],
            'username': admin[1],
            'email': admin[2],
            'role': admin[3],
            'is_active': admin[4]
        } for admin in admin_users]

        # Your existing dashboard queries
        cursor.execute("""
            SELECT ID_Number, Name, Department, Level, 
                   `Course/Strand`, Email, Gender 
            FROM clienttb
        """)
        clients = cursor.fetchall()
        
        cursor.execute("""
            SELECT ISBN, Title, Author, Publisher, Genre, CoverImage,
                total_copies, available_copies, borrowed_copies 
            FROM booktb
        """)
        books = cursor.fetchall()

        client_data = [{
            'ID_Number': client[0],
            'Name': client[1],
            'Department': client[2],
            'Level': client[3],
            'Course_Strand': client[4],
            'Email': client[5],
            'Gender': client[6]
        } for client in clients]

        book_data = [{
            'ISBN': book[0],
            'Title': book[1],
            'Author': book[2],
            'Publisher': book[3],
            'Genre': book[4],
            'CoverImage': book[5],
            'total_copies': book[6],
            'available_copies': book[7],
            'borrowed_copies': book[8]
        } for book in books]
        
        logging.info(f'Admin {session.get("admin_id")} accessed dashboard')
        return render_template('dashboard.html', 
                            admin_users=admin_data,  # Add this line
                            clients=client_data, 
                            books=book_data,
                            admin_role=session.get('admin_role'))
                            
    except Exception as e:
        logging.error(f'Dashboard error: {str(e)}')
        return redirect('/login_page')
    

@app.route('/student_dashboard')
def student_dashboard():
    auth_status = check_auth()
    if not auth_status:
        logging.warning('Unauthorized access attempt to student dashboard')
        return redirect('/login_page')
    
    try:
        student_id = session.get('student_id')
        if not student_id:
            return redirect('/login_page')

        cursor.execute("""
            SELECT * FROM clienttb 
            WHERE ID_Number = %s
        """, (student_id,))
        student_details = cursor.fetchone()
        
        if not student_details:
            session.clear()
            return redirect('/login_page')

        return render_template('student_dashboard.html', 
                            student=student_details)
    except Exception as e:
        logging.error(f'Student dashboard error: {str(e)}')
        return redirect('/login_page')

@app.route('/announcement', methods=['POST'])
def create_announcement():
    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'})
        
    try:
        data = request.get_json()
        title = data.get('title')
        content = data.get('content')
        posted_by = session.get('admin_name', 'Unknown Admin')

        cursor.execute("""
            INSERT INTO announcements (title, content, posted_by)
            VALUES (%s, %s, %s)
        """, (title, content, posted_by))
        db.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/get-announcements')
def get_announcements():
    try:
        cursor.execute("""
            SELECT id, title, content, date_posted, posted_by 
            FROM announcements 
            WHERE is_active = 1 
            ORDER BY date_posted DESC
        """)
        announcements = cursor.fetchall()
        
        announcement_list = []
        for announcement in announcements:
            announcement_list.append({
                'id': announcement[0],
                'title': announcement[1],
                'content': announcement[2],
                'date': announcement[3].strftime("%Y-%m-%d %I:%M %p"),
                'posted_by': announcement[4]
            })
        
        return jsonify(announcement_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/delete_announcement/<int:id>', methods=['DELETE'])
def delete_announcement(id):
    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'})
        
    try:
        cursor.execute("UPDATE announcements SET is_active = FALSE WHERE id = %s", (id,))
        db.commit()
        logging.info(f'Announcement {id} marked as inactive')
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f'Error deleting announcement: {str(e)}')
        return jsonify({'success': False, 'message': str(e)})

@app.route('/add_librarian', methods=['POST'])
def add_librarian():
    try:
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        password = request.form.get('password')

        if not all([username, email, role, password]):
            return jsonify({
                'success': False, 
                'message': 'All fields are required'
            })

        cursor = db.cursor()
        
        # Check for recycled IDs
        cursor.execute("""
            SELECT admin_id FROM admin_users 
            WHERE is_active = FALSE 
            ORDER BY admin_id ASC LIMIT 1
        """)
        recycled_id = cursor.fetchone()

        if recycled_id:
            # Use recycled ID
            new_id = recycled_id[0]
            cursor.execute("DELETE FROM admin_users WHERE admin_id = %s", (new_id,))
        else:
            # Generate new ID
            cursor.execute("SELECT MAX(CAST(admin_id AS SIGNED)) FROM admin_users")
            last_id = cursor.fetchone()[0]
            if last_id:
                new_id = str(int(last_id) + 1).zfill(7)
            else:
                new_id = '0000001'

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Insert new librarian
        insert_query = """
            INSERT INTO admin_users (admin_id, name, email, role, password, is_active) 
            VALUES (%s, %s, %s, %s, %s, TRUE)
        """
        cursor.execute(insert_query, (
            new_id,
            username,
            email,
            role,
            hashed_password
        ))
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': f'Librarian added successfully with ID: {new_id}'
        })
        
    except Exception as e:
        print(f"Error in add_librarian: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        })
@app.route('/get_librarians')
def get_librarians():
    try:
        cursor = mysql.connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM admin")
        librarians = cursor.fetchall()
        cursor.close()
        return jsonify({'success': True, 'librarians': librarians})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_librarian/<int:id>')
def get_librarian(id):
    try:
        cursor = db.cursor(dictionary=True)
        
        # Updated column names to match your database structure
        cursor.execute("""
            SELECT admin_id, name, email, role 
            FROM admin_users 
            WHERE admin_id = %s
        """, (id,))
        
        librarian = cursor.fetchone()
        
        if librarian:
            return jsonify({
                'success': True,
                'librarian': {
                    'id': librarian['admin_id'],
                    'username': librarian['name'],  # Changed from username to name
                    'email': librarian['email'],
                    'role': librarian['role']
                }
            })
        return jsonify({'success': False, 'message': 'Librarian not found'})
    except Exception as e:
        print(f"Error in get_librarian: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/edit_librarian/<int:id>', methods=['POST'])
def edit_librarian(id):
    try:
        cursor = db.cursor()
        
        # Get form data
        username = request.form.get('username')  # This will still be 'username' from the form
        email = request.form.get('email')
        role = request.form.get('role')
        password = request.form.get('password')
        
        if password and password.strip():
            # Update with new password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            cursor.execute("""
                UPDATE admin_users 
                SET name = %s, email = %s, role = %s, password = %s 
                WHERE admin_id = %s
            """, (username, email, role, hashed_password, id))
        else:
            # Update without changing password
            cursor.execute("""
                UPDATE admin_users 
                SET name = %s, email = %s, role = %s 
                WHERE admin_id = %s
            """, (username, email, role, id))
        
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error in edit_librarian: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete_librarian/<int:id>', methods=['DELETE'])
def delete_librarian(id):
    try:
        cursor = db.cursor()
        
        # Delete the librarian
        cursor.execute("DELETE FROM admin_users WHERE admin_id = %s", (id,))
        db.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error in delete_librarian: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

# Add login verification function
def verify_password(stored_password_hash, provided_password):
    """Verify the provided password against the stored hash"""
    return check_password_hash(stored_password_hash, provided_password)

    
@app.route('/update', methods=['POST'])
def update_records():
    try:
        for id in request.form:
            if id.startswith('name_'):
                record_id = id.split('_')[1]
                name = request.form.get(f'name_{record_id}')
                department = request.form.get(f'department_{record_id}')
                level = request.form.get(f'level_{record_id}')
                course_strand = request.form.get(f'course_strand_{record_id}')
                email = request.form.get(f'email_{record_id}')
                gender = request.form.get(f'gender_{record_id}')
                
                update_query = """
                UPDATE clienttb 
                SET Name = %s, Department = %s, Level = %s, `Course/Strand` = %s, Email = %s, Gender = %s
                WHERE ID_Number = %s
                """
                cursor.execute(update_query, (name, department, level, course_strand, email, gender, record_id))
        
        db.commit()
        logging.info('Records updated successfully')
        return redirect('/admin_dashboard')
    except Exception as e:
        logging.error(f'An error occurred: {str(e)}')
        return f'An error occurred: {str(e)}'

@app.route('/edit')
def edit():
    ids = request.args.getlist('ids')
    if ids:
        logging.debug(f'Received ids: {ids}')
        try:
            ids_list = ids
            # Fetch data for the given ids
            cursor.execute("SELECT ID_Number, Name, Department, Level, `Course/Strand`, Email, Gender FROM clienttb WHERE ID_Number IN (%s)" % ','.join(['%s'] * len(ids)), ids)
            clients = cursor.fetchall()
            
            client_data = []
            for client in clients:
                client_data.append({
                    'ID_Number': client[0],
                    'Name': client[1],
                    'Department': client[2],
                    'Level': client[3],
                    'Course_Strand': client[4],
                    'Email': client[5],
                    'Gender': client[6]
                })
            
            return render_template('edit.html', clients=client_data)
        except Exception as e:
            logging.error(f'Error rendering edit.html: {str(e)}')
            return jsonify({'success': False, 'error': str(e)})
    else:
        logging.warning('No ids parameter provided')
        return jsonify({'success': False, 'error': 'No ids parameter provided'})
    
@app.route('/delete', methods=['POST'])
def delete():
    data = request.get_json()
    ids = data['ids']
    try:
        for id in ids:
            cursor.execute("DELETE FROM clienttb WHERE ID_Number = %s", (id,))
        db.commit()
        logging.info('Records deleted successfully')
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f'An error occurred: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})
    
@app.route('/department_data', methods=['GET'])
def department_data():
    try:
        query = "SELECT Department, COUNT(*) as count FROM clienttb GROUP BY Department"
        cursor.execute(query)
        results = cursor.fetchall()
        
        data = []
        for row in results:
            data.append({'department': row[0], 'count': row[1]})
        
        logging.info('Department data fetched successfully')
        return jsonify(data)
    except mysql.connector.Error as err:
        logging.error(f'Database error occurred: {err}')
        return jsonify({'error': str(err)}), 500

@app.route('/gender_data', methods=['GET'])
def gender_data():
    query = "SELECT Gender, COUNT(*) as count FROM clienttb GROUP BY Gender"
    cursor.execute(query)
    results = cursor.fetchall()
    
    data = []
    for row in results:
        data.append({'gender': row[0], 'count': row[1]})
    
    logging.info('Gender data fetched successfully')
    return jsonify(data)

@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/librarian')
def librarian():
    try:
        # Fetch librarians from database
        cursor.execute("""
            SELECT admin_id, name, email, role 
            FROM admin_users 
            WHERE is_active = TRUE 
            ORDER BY admin_id
        """)
        librarians = cursor.fetchall()
        
        # Convert to list of dictionaries for easier template handling
        librarian_list = [{
            'admin_id': lib[0],
            'name': lib[1],
            'email': lib[2],
            'role': lib[3]
        } for lib in librarians]
        
        logging.info('Librarian data fetched successfully')
        return render_template('librarian.html', librarians=librarian_list)
    except Exception as e:
        logging.error(f'Error fetching librarian data: {str(e)}')
        return str(e)



@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
    # Clear any existing session on GET request
    if request.method == 'GET':
        session.clear()
        return render_template('login_page.html')
        
    if request.method == 'POST':
        id_number = request.form.get('ID_Number')
        
        try:
            # Check admin credentials
            cursor.execute("""
                SELECT admin_id, name, email, role 
                FROM admin_users 
                WHERE admin_id = %s AND is_active = TRUE
            """, (id_number,))
            
            admin = cursor.fetchone()
            if admin:
                session.clear()
                session['admin_id'] = admin[0]
                session['admin_name'] = admin[1]
                session['admin_email'] = admin[2]
                session['admin_role'] = admin[3]
                session['is_admin'] = True
                
                logging.info(f'Admin {id_number} logged in successfully')
                return redirect('/admin_dashboard')
            
            # Check student credentials
            cursor.execute("""
                SELECT ID_Number, Name, Email 
                FROM clienttb 
                WHERE ID_Number = %s
            """, (id_number,))
            
            student = cursor.fetchone()
            if student:
                session.clear()
                session['student_id'] = student[0]
                session['student_name'] = student[1]
                session['student_email'] = student[2]
                session['is_admin'] = False
                
                logging.info(f'Student {id_number} logged in successfully')
                return redirect('/student_dashboard')
            
            logging.warning(f'Invalid login attempt with ID: {id_number}')
            return 'Invalid ID Number'
            
        except Exception as e:
            logging.error(f'Login error: {str(e)}')
            return str(e)

@app.route('/logout')
def logout():
    session.clear()
    logging.info("Admin logged out successfully")
    return redirect('/home_page')

@app.route('/barcode_login', methods=['POST'])
def barcode_login():
    if 'barcode_image' in request.files:
        barcode_image = request.files['barcode_image']
        image = Image.open(barcode_image)
        decoded_objects = decode(image)
        
        if decoded_objects:
            barcode_data = decoded_objects[0].data.decode('utf-8')
            
            try:
                # Check if the ID_Number exists in the ClientTB table
                cursor.execute("SELECT ID_Number, Name FROM clienttb WHERE ID_Number = %s", (barcode_data,))
                student = cursor.fetchone()
                
                if student:
                    session['student_id'] = student[0]
                    session['student_name'] = student[1]
                    logging.info('Student logged in successfully via barcode')
                    return redirect('/student_dashboard.html')
                else:
                    logging.warning('Invalid barcode data')
                    return 'Invalid barcode data'
            except mysql.connector.Error as err:
                logging.error(f'Database error occurred: {err}')
                return f'Database error occurred: {err}'
            except Exception as e:
                logging.error(f'An error occurred: {str(e)}')
                return f'An error occurred: {str(e)}'
        else:
            logging.warning('No barcode detected')
            return 'No barcode detected'
    return 'No barcode image provided'

@app.route('/barcode_scan', methods=['GET', 'POST'])
def barcode_scan():
    if request.method == 'POST':
        if 'barcode_image' in request.files:
            barcode_image = request.files['barcode_image']
            image = Image.open(barcode_image)
            decoded_objects = decode(image)
            
            if decoded_objects:
                barcode_data = decoded_objects[0].data.decode('utf-8')
                
                try:
                    cursor.execute("SELECT ID_Number, Name FROM clienttb WHERE ID_Number = %s", (barcode_data,))
                    student = cursor.fetchone()
                    
                    if student:
                        session['student_id'] = student[0]
                        session['student_name'] = student[1]
                        logging.info('Barcode scanned successfully')
                        return render_template('Barcode_Scan.html', message='Barcode scanned successfully!')
                    else:
                        logging.warning('Invalid barcode data')
                        return render_template('Barcode_Scan.html', message='Invalid barcode data')
                except mysql.connector.Error as err:
                    logging.error(f'Database error occurred: {err}')
                    return render_template('Barcode_Scan.html', message=f'Database error occurred: {err}')
                except Exception as e:
                    logging.error(f'An error occurred: {str(e)}')
                    return render_template('Barcode_Scan.html', message=f'An error occurred: {str(e)}')
            else:
                logging.warning('No barcode detected')
                return render_template('Barcode_Scan.html', message='No barcode detected')
        return render_template('Barcode_Scan.html', message='No barcode image provided')
    return render_template('Barcode_Scan.html')
   

def validate_lcc(call_number):
    """Validate Library of Congress Call Number format"""
    # Remove extra spaces and trim
    call_number = ' '.join(call_number.split())
    
    # More flexible pattern to match various LCC formats including cutter numbers
    import re
    lcc_pattern = r'^[A-Z]+\s*\d+(\.\d+)?(\s*\.[A-Z][A-Z0-9]+)?(\s+\d{4})?$'
    
    return bool(re.match(lcc_pattern, call_number))

@app.route('/BookInput', methods=['GET', 'POST'])
def BookInput():
    if not session.get('is_admin'):
        logging.warning('Unauthorized access attempt to BookInput')
        return redirect('/login_page')
    
    if request.method == 'POST':
        data = request.get_json()
        search_type = data.get('search_type')
        search_value = data.get('search_value')

        try:
            if search_type == 'isbn':
                # ISBN handling remains the same
                formatted_isbn = search_value.replace('-', '').replace(' ', '')
                response = requests.get(f'https://www.googleapis.com/books/v1/volumes?q=isbn:{formatted_isbn}')
                book_data = response.json()

                if 'items' in book_data:
                    book_info = book_data['items'][0]['volumeInfo']
                    return jsonify(success=True,
                                 title=book_info.get('title', 'Unknown Title'),
                                 authors=', '.join(book_info.get('authors', ['Unknown Author'])),
                                 publisher=book_info.get('publisher', 'Unknown Publisher'),
                                 genre=', '.join(book_info.get('categories', ['Unknown Genre'])),
                                 cover_image=book_info.get('imageLinks', {}).get('thumbnail', ''),
                                 isbn=formatted_isbn)

            elif search_type == 'lcc':
                # Clean and validate call number
                call_number = ' '.join(search_value.split())
                
                # Try LC API search with the full call number first
                lcc_response = requests.get(
                    f'https://www.loc.gov/books/?fo=json&q={call_number}',
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                
                if lcc_response.status_code == 200:
                    lcc_data = lcc_response.json()
                    
                    if 'results' in lcc_data and len(lcc_data['results']) > 0:
                        book_info = lcc_data['results'][0]
                        
                        # Process author information
                        author = book_info.get('contributor', [])
                        if isinstance(author, list):
                            author = author[0] if author else 'Unknown Author'
                        
                        # Process publisher information
                        publisher = book_info.get('publisher', [])
                        if isinstance(publisher, list):
                            publisher = publisher[0] if publisher else 'Unknown Publisher'
                        
                        # Process subject/genre information
                        subject = book_info.get('subject', [])
                        if isinstance(subject, list):
                            subject = subject[0] if subject else 'Unknown Genre'
                        
                        return jsonify(success=True,
                                     title=book_info.get('title', 'Unknown Title'),
                                     authors=author,
                                     publisher=publisher,
                                     genre=subject,
                                     cover_image=book_info.get('image_url', ''),
                                     lcc=call_number)

            return jsonify(success=False, message='No book data found')

        except requests.exceptions.RequestException as e:
            logging.error(f'API request error: {str(e)}')
            return jsonify(success=False, message=f'API request error: {str(e)}')
        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return jsonify(success=False, message=f'An error occurred: {str(e)}')

    return render_template('BookInput.html')

@app.route('/insert_book', methods=['POST'])
def insert_book():
    data = request.get_json()
    search_type = data.get('search_type')
    search_value = data.get('search_value')

    try:
        if search_type == 'isbn':
            formatted_isbn = search_value.replace('-', '').replace(' ', '')
            response = requests.get(f'https://www.googleapis.com/books/v1/volumes?q=isbn:{formatted_isbn}')
            book_data = response.json()

            if 'items' in book_data:
                book_info = book_data['items'][0]['volumeInfo']
                
                # Handle authors list
                authors = book_info.get('authors', ['Unknown Author'])
                if isinstance(authors, list):
                    authors = ', '.join(authors)
                else:
                    authors = str(authors)

                # Handle categories list
                categories = book_info.get('categories', ['Unknown Genre'])
                if isinstance(categories, list):
                    categories = ', '.join(categories)
                else:
                    categories = str(categories)

                # Handle publisher
                publisher = book_info.get('publisher', 'Unknown Publisher')
                if isinstance(publisher, list):
                    publisher = ', '.join(publisher)

                # Handle cover image
                cover_image = book_info.get('imageLinks', {})
                if isinstance(cover_image, dict):
                    cover_image = cover_image.get('thumbnail', '')
                else:
                    cover_image = ''

                insert_query = """
                INSERT INTO booktb (ISBN, Title, Author, Publisher, Genre, CoverImage) 
                VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, (
                    formatted_isbn,
                    str(book_info.get('title', 'Unknown Title')),
                    authors,
                    publisher,
                    categories,
                    cover_image
                ))

        elif search_type == 'lcc':
            call_number = ' '.join(search_value.split())
            
            lcc_response = requests.get(
                f'https://www.loc.gov/books/?fo=json&q={call_number}',
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            lcc_data = lcc_response.json()

            if 'results' in lcc_data and len(lcc_data['results']) > 0:
                book_info = lcc_data['results'][0]
                
                # Handle contributor/author
                author = book_info.get('contributor', ['Unknown Author'])
                if isinstance(author, list):
                    author = ', '.join(filter(None, author))
                else:
                    author = str(author)

                # Handle publisher
                publisher = book_info.get('publisher', ['Unknown Publisher'])
                if isinstance(publisher, list):
                    publisher = ', '.join(filter(None, publisher))
                else:
                    publisher = str(publisher)

                # Handle subject/genre
                subject = book_info.get('subject', ['Unknown Genre'])
                if isinstance(subject, list):
                    subject = ', '.join(filter(None, subject))
                else:
                    subject = str(subject)

                insert_query = """
                INSERT INTO booktb (ISBN, Title, Author, Publisher, Genre, CoverImage, LCC) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, (
                    'LCC-' + call_number,
                    str(book_info.get('title', 'Unknown Title')),
                    author,
                    publisher,
                    subject,
                    str(book_info.get('image_url', '')),
                    call_number
                ))

        db.commit()
        logging.info('Book data inserted successfully')
        return jsonify(success=True, message='Book data inserted successfully')

    except Exception as e:
        logging.error(f'An error occurred: {str(e)}')
        return jsonify(success=False, message=f'An error occurred: {str(e)}')
@app.route('/delete_books', methods=['POST'])
def delete_books():
    data = request.get_json()
    ids = data['ids']
    try:
        # Delete from booktb
        for isbn in ids:
            cursor.execute("DELETE FROM booktb WHERE ISBN = %s", (isbn,))
        
        # Assuming you want to delete from clienttb based on some related field
        # For example, if ISBN is related to a field in clienttb, replace `RelatedField` with the actual field name
        
        db.commit()
        logging.info('Books and related client records deleted successfully')
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f'An error occurred: {str(e)}')
        return jsonify({'success': False, 'error': str(e)})

    
@app.route('/update_book_copies', methods=['POST'])
def update_book_copies():
    try:
        data = request.get_json()
        isbn = data.get('isbn')
        total_copies = int(data.get('total_copies', 0))
        available_copies = int(data.get('available_copies', 0))
        borrowed_copies = int(data.get('borrowed_copies', 0))
        
        # Update the book record
        cursor.execute("""
            UPDATE booktb 
            SET total_copies = %s,
                available_copies = %s,
                borrowed_copies = %s
            WHERE ISBN = %s
        """, (total_copies, available_copies, borrowed_copies, isbn))
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': 'Book copies updated successfully',
            'total_copies': total_copies,
            'available_copies': available_copies,
            'borrowed_copies': borrowed_copies
        })
        
    except Exception as e:
        print(f"Error updating book copies: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error updating book copies'
        })
    
@app.route('/get_book_copies/<isbn>')
def get_book_copies(isbn):
    try:
        cursor.execute("""
            SELECT total_copies, available_copies, borrowed_copies 
            FROM booktb 
            WHERE ISBN = %s
        """, (isbn,))
        
        result = cursor.fetchone()
        if result:
            return jsonify({
                'success': True,
                'total_copies': result[0] or 0,
                'available_copies': result[1] or 0,
                'borrowed_copies': result[2] or 0
            })
        return jsonify({
            'success': False,
            'message': 'Book not found'
        })
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error fetching book copies'
        })

    
if __name__ == '__main__':
    app.run(debug=True)