from flask import Flask, render_template, request, redirect, jsonify, session, url_for, flash
import logging
# from pyzbar.pyzbar import decode
from PIL import Image
import requests
import mysql.connector 
from mysql.connector import Error as DBError
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash 
from functools import wraps
from datetime import datetime, timedelta
import os


app = Flask(__name__)
app.secret_key = "SPCLibrary"

db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="librarymanagent", )

cursor = db.cursor()

def validate_lcc(call_number):
    """Validate Library of Congress Call Number format"""
    # Remove extra spaces and trim
    call_number = ' '.join(call_number.split())
    
    # More flexible pattern to match various LCC formats including cutter numbers
    import re
    lcc_pattern = r'^[A-Z]+\s*\d+(\.\d+)?(\s*\.[A-Z][A-Z0-9]+)?(\s+\d{4})?$'
    
    return bool(re.match(lcc_pattern, call_number))

def convert_timedelta_to_date(timedelta_obj):
    # Convert timedelta to date assuming it represents a duration from a base date
    return (datetime.min + timedelta_obj).date()

def convert_timedelta_to_time(timedelta_obj):
    """Convert timedelta to time assuming it represents a duration from midnight."""
    return (datetime.min + timedelta_obj).time()

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
        'get-announcements',
        'get_public_librarians'  # Add this line
    }
    
    # Allow access to public routes and static files
    if endpoint in PUBLIC_ROUTES or endpoint == 'static':
        return True
        
    # For protected routes, check authentication
    if endpoint not in PUBLIC_ROUTES:
        if 'loggedin' not in session:
            return redirect(url_for('login_page'))
            
    return True

@app.route('/announcement')
def announcement():
    return render_template('announcement.html')

@app.route('/create_announcement', methods=['POST'])
def create_announcement():
    try:
        cursor = db.cursor(dictionary=True)
        
        title = request.form.get('title')
        message = request.form.get('message')
        date = request.form.get('date')
        priority = request.form.get('priority', 'medium')  # Default to medium if not specified
        
        # Validate priority
        valid_priorities = ['low', 'medium', 'high']
        if priority not in valid_priorities:
            priority = 'medium'
        
        query = """
            INSERT INTO announcements (title, message, date, priority)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (title, message, date, priority))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Announcement created successfully'})
    except Exception as e:
        if db:
            db.rollback()
        logging.error(f'Error creating announcement: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/get_announcements')
def get_announcements():
    try:
        cursor = db.cursor(dictionary=True)
        
        query = """
            SELECT * FROM announcements 
            ORDER BY 
                CASE priority
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END,
                date DESC, 
                created_at DESC
        """
        cursor.execute(query)
        announcements = cursor.fetchall()
        
        # Convert datetime objects to string format
        for announcement in announcements:
            announcement['date'] = announcement['date'].strftime('%Y-%m-%d')
            if announcement['created_at']:
                announcement['created_at'] = announcement['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        
        return jsonify({
            'success': True,
            'announcements': announcements
        })
    except Exception as e:
        logging.error(f'Error fetching announcements: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/delete_announcement/<int:id>', methods=['DELETE'])
def delete_announcement(id):
    try:
        cursor = db.cursor()
        
        query = "DELETE FROM announcements WHERE id = %s"
        cursor.execute(query, (id,))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Announcement deleted successfully'})
    except Exception as e:
        if db:
            db.rollback()
        logging.error(f'Error deleting announcement: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update_announcement/<int:id>', methods=['PUT'])
def update_announcement(id):
    try:
        cursor = db.cursor()
        data = request.get_json()
        
        title = data.get('title')
        message = data.get('message')
        date = data.get('date')
        priority = data.get('priority', 'medium')
        
        # Validate priority
        valid_priorities = ['low', 'medium', 'high']
        if priority not in valid_priorities:
            priority = 'medium'
        
        query = """
            UPDATE announcements 
            SET title = %s, message = %s, date = %s, priority = %s
            WHERE id = %s
        """
        cursor.execute(query, (title, message, date, priority, id))
        db.commit()
        
        return jsonify({'success': True, 'message': 'Announcement updated successfully'})
    except Exception as e:
        if db:
            db.rollback()
        logging.error(f'Error updating announcement: {str(e)}')
        return jsonify({'success': False, 'message': str(e)}), 500

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
        cursor.execute("SELECT ISBN, CoverImage, Title, Author, Genre, total_copies, available_copies, borrowed_copies FROM booktb")
        books_data = cursor.fetchall()
        
        books = []
        for book in books_data:
            books.append({
                'ISBN': book[0],
                'CoverImage': book[1],
                'Title': book[2],
                'Author': book[3],
                'Genre': book[4],
                'Total_copies': book[5],
                'Available_copies': book[6],
                'Borrowed_copies': book[7]
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
        if session.get('is_representative'):
            return 'representative'
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
                   `Course/Strand`, Email, Gender, Representative 
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
            'Gender': client[6],
            'Representative': client[7]
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

        # Fetch student details
        cursor.execute("""
            SELECT ID_Number, Name FROM clienttb 
            WHERE ID_Number = %s
        """, (student_id,))
        student_details = cursor.fetchone()
        
        if not student_details:
            session.clear()
            return redirect('/login_page')

        # Fetch borrowed books with their details
        cursor.execute("""
            SELECT 
                b.Title,
                b.Author,
                br.borrow_date,
                br.due_date,
                CASE
                    WHEN br.due_date < CURDATE() THEN 'overdue'
                    WHEN br.due_date = CURDATE() THEN 'due today'
                    WHEN br.due_date <= DATE_ADD(CURDATE(), INTERVAL 3 DAY) THEN 'due soon'
                    ELSE 'on time'
                END as status,
                CASE
                    WHEN br.due_date < CURDATE() THEN 'status-overdue'
                    WHEN br.due_date = CURDATE() THEN 'status-due-today'
                    WHEN br.due_date <= DATE_ADD(CURDATE(), INTERVAL 3 DAY) THEN 'status-due-soon'
                    ELSE 'status-on-time'
                END as status_class
            FROM borrow_records br
            JOIN booktb b ON br.book_isbn = b.ISBN
            WHERE br.client_id = %s
            AND br.status = 'borrowed'
            ORDER BY br.due_date ASC
        """, (student_id,))
        
        borrowed_books = []
        for book in cursor.fetchall():
            borrowed_books.append({
                'title': book[0],
                'author': book[1],
                'borrowed_date': book[2],
                'due_date': book[3],
                'status': book[4],
                'status_class': book[5]
            })

        student = {
            'ID_Number': student_details[0],
            'Name': student_details[1]
        }

        return render_template('student_dashboard.html',
                            student=student,
                            books_borrowed=borrowed_books)

    except Exception as e:
        logging.error(f'Student dashboard error: {str(e)}')
        return redirect('/login_page')

@app.route('/get_student_books/<student_id>')
def get_student_books(student_id):
    """
    API endpoint to fetch borrowed books for a specific student
    """
    try:
        cursor.execute("""
            SELECT 
                b.Title,
                b.Author,
                br.borrow_date,
                br.due_date,
                CASE
                    WHEN br.due_date < CURDATE() THEN 'overdue'
                    WHEN br.due_date = CURDATE() THEN 'due today'
                    WHEN br.due_date <= DATE_ADD(CURDATE(), INTERVAL 3 DAY) THEN 'due soon'
                    ELSE 'on time'
                END as status
            FROM borrow_records br
            JOIN booktb b ON br.book_isbn = b.ISBN
            WHERE br.client_id = %s
            AND br.status = 'borrowed'
            ORDER BY br.due_date ASC
        """, (student_id,))
        
        books = cursor.fetchall()
        books_list = []
        
        for book in books:
            books_list.append({
                'title': book[0],
                'author': book[1],
                'borrowed_date': book[2].strftime('%Y-%m-%d') if book[2] else None,
                'due_date': book[3].strftime('%Y-%m-%d') if book[3] else None,
                'status': book[4]
            })
            
        return jsonify({
            'success': True,
            'books': books_list
        })
        
    except Exception as e:
        logging.error(f'Error fetching student books: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/extend_due_date', methods=['POST'])
def extend_due_date():
    """
    Endpoint to handle book due date extension requests
    """
    try:
        data = request.get_json()
        student_id = data.get('student_id')
        book_isbn = data.get('book_isbn')
        
        # Verify if the student can extend (e.g., not already extended, not overdue)
        cursor.execute("""
            SELECT br.id, br.due_date, br.extensions_count
            FROM borrow_records br
            WHERE br.client_id = %s 
            AND br.book_isbn = %s
            AND br.status = 'borrowed'
        """, (student_id, book_isbn))
        
        record = cursor.fetchone()
        
        if not record:
            return jsonify({
                'success': False,
                'message': 'No active borrowing record found'
            }), 404
            
        if record[2] >= 2:  # Maximum 2 extensions allowed
            return jsonify({
                'success': False,
                'message': 'Maximum number of extensions reached'
            }), 400
            
        # Extend due date by 7 days
        new_due_date = record[1] + timedelta(days=7)
        
        cursor.execute("""
            UPDATE borrow_records
            SET due_date = %s,
                extensions_count = extensions_count + 1
            WHERE id = %s
        """, (new_due_date, record[0]))
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': 'Due date extended successfully',
            'new_due_date': new_due_date.strftime('%Y-%m-%d')
        })
        
    except Exception as e:
        logging.error(f'Error extending due date: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500



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
        cursor = db.cursor(dictionary=True)
        # Update the query to match your admin_users table structure
        cursor.execute("""
            SELECT name, email, role 
            FROM admin_users 
            WHERE is_active = TRUE
            ORDER BY role, name
        """)
        librarians = cursor.fetchall()
        cursor.close()
        
        return jsonify({
            'success': True,
            'librarians': librarians
        })
    except Exception as e:
        print(f"Error fetching librarians: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })



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

@app.route('/librarian')
def librarian_page():
    """Route to display the librarian page"""
    return render_template('librarian.html')

@app.route('/get_public_librarians')
def get_public_librarians():
    """API endpoint to fetch public librarian information"""
    try:
        cursor = mysql.connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT name, email, role 
            FROM admin_users 
            WHERE is_active = TRUE 
            ORDER BY 
                CASE 
                    WHEN role = 'Head Librarian' THEN 1
                    WHEN role = 'Librarian' THEN 2
                    ELSE 3 
                END,
                name ASC
        """)
        librarians = cursor.fetchall()
        cursor.close()
        
        return jsonify({
            'success': True,
            'librarians': librarians
        })
    except Exception as e:
        print(f"Error fetching librarians: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Unable to fetch librarian information'
        }), 500

    
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
                representative = request.form.get(f'representative_{record_id}') == 'on'
                
                update_query = """
                UPDATE clienttb 
                SET Name = %s, Department = %s, Level = %s, `Course/Strand` = %s, Email = %s, Gender = %s, Representative = %s

                WHERE ID_Number = %s
                """
                cursor.execute(update_query, (name, department, level, course_strand, email, gender, representative,record_id))
        
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
            cursor.execute("SELECT ID_Number, Name, Department, Level, `Course/Strand`, Email, Gender, Representative FROM clienttb WHERE ID_Number IN (%s)" % ','.join(['%s'] * len(ids)), ids)
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
                    'Gender': client[6],
                    'Representative': client[7]
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
            
            # Check student/representative credentials
            cursor.execute("""
                SELECT ID_Number, Name, Email, Representative 
                FROM clienttb 
                WHERE ID_Number = %s
            """, (id_number,))
            
            user = cursor.fetchone()
            if user:
                session.clear()
                session['student_id'] = user[0]
                session['student_name'] = user[1]
                session['student_email'] = user[2]
                session['is_representative'] = bool(user[3])  # Convert to boolean
                session['is_admin'] = False
                
                logging.info(f'User {id_number} logged in successfully as {"representative" if user[3] else "student"}')
                
                # Redirect based on role
                if user[3]:  # If Representative is True
                    return redirect('/representative_dashboard')
                else:
                    return redirect('/student_dashboard')
            
            logging.warning(f'Invalid login attempt with ID: {id_number}')
            return 'Invalid ID Number'
            
        except Exception as e:
            logging.error(f'Login error: {str(e)}')
            return str(e)

@app.route('/representative_dashboard')
def representative_dashboard():
    auth_status = check_auth()
    if not auth_status:
        logging.warning('Unauthorized access attempt to representative dashboard')
        return redirect('/login_page')
    
    try:
        rep_id = session.get('student_id')
        if not rep_id:
            return redirect('/login_page')

        # Verify the user is actually a representative
        cursor.execute("""
            SELECT ID_Number, Name FROM clienttb 
            WHERE ID_Number = %s AND Representative = TRUE
        """, (rep_id,))
        rep_details = cursor.fetchone()
        
        if not rep_details:
            session.clear()
            return redirect('/login_page')

        # Fetch borrowed books with their details
        cursor.execute("""
            SELECT 
                b.Title,
                b.Author,
                br.borrow_date,
                br.due_date,
                CASE
                    WHEN br.due_date < CURDATE() THEN 'overdue'
                    WHEN br.due_date = CURDATE() THEN 'due today'
                    WHEN br.due_date <= DATE_ADD(CURDATE(), INTERVAL 3 DAY) THEN 'due soon'
                    ELSE 'on time'
                END as status,
                CASE
                    WHEN br.due_date < CURDATE() THEN 'status-overdue'
                    WHEN br.due_date = CURDATE() THEN 'status-due-today'
                    WHEN br.due_date <= DATE_ADD(CURDATE(), INTERVAL 3 DAY) THEN 'status-due-soon'
                    ELSE 'status-on-time'
                END as status_class
            FROM borrow_records br
            JOIN booktb b ON br.book_isbn = b.ISBN
            WHERE br.client_id = %s
            AND br.status = 'borrowed'
            ORDER BY br.due_date ASC
        """, (rep_id,))
        
        borrowed_books = []
        for book in cursor.fetchall():
            borrowed_books.append({
                'title': book[0],
                'author': book[1],
                'borrowed_date': book[2],
                'due_date': book[3],
                'status': book[4],
                'status_class': book[5]
            })

        rep = {
            'ID_Number': rep_details[0],
            'Name': rep_details[1]
        }

        return render_template('Representative_Dashboard.html',
                            rep=rep,
                            books_borrowed=borrowed_books)

    except Exception as e:
        logging.error(f'Representative dashboard error: {str(e)}')
        return redirect('/login_page')

@app.route('/rep_request_book', methods=['GET', 'POST'])
def rep_request_book():
    # Check if user is logged in and is a representative
    if not session.get('student_id') or not session.get('is_representative'):
        logging.warning('Unauthorized access attempt to representative book request page')
        flash('Access denied. Representatives only.', 'error')
        return redirect('/login_page')

    try:
        rep_id = session.get('student_id')
        
        # Verify representative status in database
        cursor.execute("""
            SELECT ID_Number, Name, Representative 
            FROM clienttb 
            WHERE ID_Number = %s AND Representative = TRUE
        """, (rep_id,))
        
        rep_details = cursor.fetchone()
        if not rep_details:
            session.clear()
            flash('Your account is not authorized as a representative.', 'error')
            return redirect('/login_page')

        if request.method == 'POST':
            book_title = request.form.get('bookTitle')
            author = request.form.get('author')
            description = request.form.get('description')
            notes = request.form.get('notes')
            
            # Handle image upload
            book_image = request.files.get('bookImage')
            image_path = None
            
            if book_image and book_image.filename:
                filename = secure_filename(book_image.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                new_filename = f"{timestamp}_{filename}"
                upload_dir = os.path.join('static', 'book_requests')
                os.makedirs(upload_dir, exist_ok=True)
                image_path = os.path.join('book_requests', new_filename)
                book_image.save(os.path.join('static', image_path))

            try:
                cursor.execute("""
                    INSERT INTO book_requests 
                    (representative_id, book_title, author, description, notes, image_path, request_date)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """, (rep_id, book_title, author, description, notes, image_path))
                
                db.commit()
                flash('Book request submitted successfully!', 'success')
                return redirect('/representative_dashboard')
                
            except DBError as e:
                db.rollback()
                logging.error(f'Database error: {str(e)}')
                flash('Error submitting request. Please try again.', 'error')
                return redirect('/rep_request_book')

        # GET request - display form
        return render_template('rep_request_book.html', rep=rep_details)

    except Exception as e:
        logging.error(f'Book request error: {str(e)}')
        flash('An error occurred. Please try again.', 'error')
        return redirect('/login_page')
                     
@app.route('/logout')
def logout():
    session.clear()
    logging.info("User logged out successfully")
    return redirect('/')  # Changed from '/home_page' to '/'

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
        # Query the database for the specific book's copy information
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
        
        # If no book found, return zeros
        return jsonify({
            'success': True,
            'total_copies': 0,
            'available_copies': 0,
            'borrowed_copies': 0
        })
        
    except mysql.connector.Error as db_error:
        # Log database errors
        logging.error(f"Database error in get_book_copies: {str(db_error)}")
        return jsonify({
            'success': False,
            'message': 'Database error occurred',
            'total_copies': 0,
            'available_copies': 0,
            'borrowed_copies': 0
        }), 500
        
    except Exception as e:
        # Log unexpected errors
        logging.error(f"Unexpected error in get_book_copies: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An unexpected error occurred',
            'total_copies': 0,
            'available_copies': 0,
            'borrowed_copies': 0
        }), 500


@app.route('/admin_clock_in_out', methods=['GET', 'POST'])
def admin_clock_in_out():
    auth_status = check_auth()
    if not auth_status or auth_status != 'admin':
        logging.warning('Unauthorized access attempt to clock in/out page')
        return redirect('/login_page')
    
    student_details = None
    attendance_records = []
    
    if request.method == 'POST':
        id_number = request.form.get('ID_Number', '').strip()
        action = request.form.get('action')
        
        if id_number:
            try:
                # Fetch student details
                cursor.execute("""
                    SELECT ID_Number, Name, Department, Level, `Course/Strand`, Gender
                    FROM clienttb
                    WHERE ID_Number = %s
                """, (id_number,))
                student_details = cursor.fetchone()
                
                if not student_details:
                    flash('Student ID not found', 'error')
                else:
                    current_time = datetime.now()
                    current_date = current_time.date()
                    
                    # Check latest attendance status for today
                    cursor.execute("""
                        SELECT id, time_in, time_out, status
                        FROM attendance 
                        WHERE student_id = %s AND date = %s
                        ORDER BY time_in DESC
                        LIMIT 1
                    """, (id_number, current_date))
                    latest_record = cursor.fetchone()
                    
                    if action == 'clock_in':
                        if not latest_record or (latest_record and latest_record[2]):  # No record or last record has time_out
                            # Get next session number
                            cursor.execute("""
                                SELECT COALESCE(MAX(session), 0) + 1
                                FROM attendance
                                WHERE student_id = %s AND date = %s
                            """, (id_number, current_date))
                            next_session = cursor.fetchone()[0]
                            
                            # Create new attendance record
                            cursor.execute("""
                                INSERT INTO attendance 
                                (student_id, date, time_in, status, session) 
                                VALUES (%s, %s, %s, 'Present', %s)
                            """, (id_number, current_date, current_time.time(), next_session))
                            flash('Successfully clocked in', 'success')
                        else:
                            flash('Must clock out before clocking in again', 'warning')
                            
                    elif action == 'clock_out':
                        if latest_record and not latest_record[2]:  # if no time_out
                            # Update existing record with time_out
                            cursor.execute("""
                                UPDATE attendance 
                                SET time_out = %s, status = 'Out'
                                WHERE id = %s
                            """, (current_time.time(), latest_record[0]))
                            flash('Successfully clocked out', 'success')
                        else:
                            flash('No active clock-in record found', 'warning')
                    
                    db.commit()
              
                # Fetch attendance records for the student
                cursor.execute("""
                    SELECT c.ID_Number, c.Name, c.Department, c.Level, 
                           c.`Course/Strand`, c.Gender, 
                           a.date, a.time_in, a.time_out, a.status, a.session
                    FROM attendance a
                    JOIN clienttb c ON a.student_id = c.ID_Number
                    WHERE c.ID_Number = %s
                    ORDER BY a.date DESC, a.session DESC, a.time_in DESC
                    LIMIT 100
                """, (id_number,))
                attendance_records = cursor.fetchall()
                
                # Convert timedelta to time for template rendering
                attendance_records = [
                    (
                        record[0],
                        record[1],
                        record[2],
                        record[3],
                        record[4],
                        record[5],
                        record[6],
                        convert_timedelta_to_time(record[7]) if isinstance(record[7], timedelta) else record[7],
                        convert_timedelta_to_time(record[8]) if isinstance(record[8], timedelta) else record[8],
                        record[9],
                        record[10]  # session number
                    )
                    for record in attendance_records
                ]
                
                logging.info(f'Student {id_number} attendance processed')
            
            except Exception as e:
                db.rollback()
                logging.error(f'Error processing attendance: {str(e)}')
                flash('An error occurred while processing attendance', 'error')
    
    try:
        # Fetch all attendance records for initial table load
        if not attendance_records:
            cursor.execute("""
                SELECT c.ID_Number, c.Name, c.Department, c.Level, 
                       c.`Course/Strand`, c.Gender,
                       a.date, a.time_in, a.time_out, a.status, a.session
                FROM attendance a
                JOIN clienttb c ON a.student_id = c.ID_Number
                ORDER BY a.date DESC, a.session DESC, a.time_in DESC
                LIMIT 100
            """)
            attendance_records = cursor.fetchall()
            
            # Convert timedelta to time for template rendering
            attendance_records = [
                (
                    record[0],
                    record[1],
                    record[2],
                    record[3],
                    record[4],
                    record[5],
                    record[6],
                    convert_timedelta_to_time(record[7]) if isinstance(record[7], timedelta) else record[7],
                    convert_timedelta_to_time(record[8]) if isinstance(record[8], timedelta) else record[8],
                    record[9],
                    record[10]  # session number
                )
                for record in attendance_records
            ]
    except Exception as e:
        logging.error(f'Error fetching attendance records: {str(e)}')
        flash('Error fetching attendance records', 'error')
        attendance_records = []

    return render_template(
        'admin_clock_in_out.html',
        student=student_details,
        attendance_records=attendance_records
    )

@app.route('/archive_attendance', methods=['POST'])
def archive_attendance():
    auth_status = check_auth()
    if not auth_status or auth_status != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized access'})
    
    try:
        # Create archive table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS attendance_archive (
                id INT AUTO_INCREMENT PRIMARY KEY,
                student_id VARCHAR(255),
                date DATE,
                time_in TIME,
                time_out TIME,
                status VARCHAR(50),
                session INT,
                archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (student_id) REFERENCES clienttb(ID_Number)
            )
        """)

        # Move current records to archive
        cursor.execute("""
            INSERT INTO attendance_archive (student_id, date, time_in, time_out, status, session)
            SELECT student_id, date, time_in, time_out, status, session
            FROM attendance
        """)

        # Clear current attendance table
        cursor.execute("TRUNCATE TABLE attendance")

        # Commit the transaction
        db.commit()

        return jsonify({
            'success': True,
            'message': 'Records successfully archived'
        })

    except Exception as e:
        db.rollback()
        logging.error(f'Error archiving attendance records: {str(e)}')
        return jsonify({
            'success': False,
            'message': 'An error occurred while archiving records'
        })

@app.route('/attendance_data_dayofweek')
def attendance_data_dayofweek():
    try:
        # Query attendance grouped by department and day of week
        query_day_of_week = """
            SELECT 
                c.Department AS department,
                DAYNAME(a.date) AS day_of_week,
                COUNT(*) AS count
            FROM attendance a
            JOIN clienttb c ON a.student_id = c.ID_Number
            GROUP BY c.Department, DAYNAME(a.date)
            ORDER BY c.Department, day_of_week
        """
        cursor.execute(query_day_of_week)
        rows = cursor.fetchall()

        # Transform to JSON-friendly list of dicts
        data = []
        for row in rows:
            data.append({
                'department': row[0],
                'day_of_week': row[1],
                'count': row[2]
            })
        return jsonify(data), 200
    except Exception as e:
        logging.error(f"Error fetching day of week data: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/attendance_data_weekofmonth')
def attendance_data_weekofmonth():
    try:
        query_week_of_month = """
            SELECT
                c.Department AS department,
                ((DAYOFMONTH(a.date) - 1) DIV 7) + 1 AS week_of_month,
                COUNT(*) AS count
            FROM attendance a
            JOIN clienttb c ON a.student_id = c.ID_Number
            GROUP BY c.Department, ((DAYOFMONTH(a.date) - 1) DIV 7) + 1
            ORDER BY c.Department, week_of_month
        """
        cursor.execute(query_week_of_month)
        rows = cursor.fetchall()

        data = []
        for row in rows:
            data.append({
                'department': row[0],
                'week_of_month': row[1],
                'count': row[2]
            })
        return jsonify(data), 200
    except Exception as e:
        logging.error(f"Error fetching week of month data: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/attendance_data_hourofday')
def attendance_data_hourofday():
    try:
        query_hour_of_day = """
            SELECT
                c.Department AS department,
                HOUR(a.time_in) AS hour_of_day,
                COUNT(*) AS count
            FROM attendance a
            JOIN clienttb c ON a.student_id = c.ID_Number
            WHERE a.time_in IS NOT NULL
            GROUP BY c.Department, HOUR(a.time_in)
            ORDER BY c.Department, hour_of_day
        """
        cursor.execute(query_hour_of_day)
        rows = cursor.fetchall()

        data = []
        for row in rows:
            data.append({
                'department': row[0],
                'hour_of_day': row[1],
                'count': row[2]
            })
        return jsonify(data), 200
    except Exception as e:
        logging.error(f"Error fetching hour of day data: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/borrow_book', methods=['POST'])
def borrow_book():
    """
    Records a borrow transaction by inserting into the `borrow_records` table.
    Expects JSON payload with keys: clientID, bookISBN, borrowDate, returnDate
    """
    try:
        data = request.get_json()
        client_id = data.get('clientID')
        book_isbn = data.get('bookISBN')
        borrow_date = data.get('borrowDate')
        due_date = data.get('returnDate')  # "Expected return date"

        # Validation checks
        if not (client_id and book_isbn and borrow_date and due_date):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Insert record into borrow_records
        insert_query = """
            INSERT INTO borrow_records (client_id, book_isbn, borrow_date, due_date)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_query, (client_id, book_isbn, borrow_date, due_date))
        db.commit()

        # Optionally decrement available copies / increment borrowed copies in booktb
        cursor.execute("""
            UPDATE booktb
            SET 
                available_copies = available_copies - 1, 
                borrowed_copies = borrowed_copies + 1
            WHERE ISBN = %s
        """, (book_isbn,))
        db.commit()

        return jsonify({'success': True, 'message': 'Book borrowed successfully'})
    except Exception as e:
        db.rollback()
        logging.error(f"/borrow_book error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/return_book', methods=['POST'])
def return_book():
    """
    Marks a borrowed book as returned by setting return_date and updating status.
    Expects JSON payload with keys: borrow_id (PK in borrow_records)
    """
    try:
        data = request.get_json()
        borrow_id = data.get('borrow_id')

        if not borrow_id:
            return jsonify({'success': False, 'message': 'Missing borrow_id'}), 400

        # Update the borrow_records table
        current_date = datetime.now().date()
        update_query = """
            UPDATE borrow_records
            SET return_date = %s,
                status = 'returned'
            WHERE id = %s
        """
        cursor.execute(update_query, (current_date, borrow_id))
        db.commit()

        # (Optional) figure out which book was returned to update the book table
        cursor.execute("SELECT book_isbn FROM borrow_records WHERE id = %s", (borrow_id,))
        result = cursor.fetchone()
        if result:
            returned_isbn = result[0]
            # increment available copies, decrement borrowed copies
            cursor.execute("""
                UPDATE booktb
                SET 
                    available_copies = available_copies + 1,
                    borrowed_copies = borrowed_copies - 1
                WHERE ISBN = %s
            """, (returned_isbn,))
            db.commit()

        return jsonify({'success': True, 'message': 'Book returned successfully'})
    except Exception as e:
        db.rollback()
        logging.error(f"/return_book error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/borrow_records_data', methods=['GET'])
def borrow_records_data():
    """
    Fetches borrowing history from the `borrow_records` table, joining the
    clients and books for more user-friendly output.
    Returns JSON or you can render a template if you want to show it as HTML.
    """
    try:
        query = """
            SELECT
                br.id,
                br.client_id,
                c.Name AS client_name,
                br.book_isbn,
                b.Title AS book_title,
                br.borrow_date,
                br.due_date,
                br.return_date,
                br.status
            FROM borrow_records br
            JOIN clienttb c ON br.client_id = c.ID_Number
            JOIN booktb b ON br.book_isbn = b.ISBN
            ORDER BY br.id DESC
        """
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Format results
        records = []
        for row in results:
            records.append({
                'borrow_id': row[0],
                'client_id': row[1],
                'client_name': row[2],
                'book_isbn': row[3],
                'book_title': row[4],
                'borrow_date': str(row[5]),
                'due_date': str(row[6]),
                'return_date': str(row[7]) if row[7] else None,
                'status': row[8]
            })
        
        return jsonify({'success': True, 'borrow_records': records})
    except Exception as e:
        logging.error(f"Error fetching borrow_records_data: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/borrow_history')
def borrow_history():
    """
    Renders a simple template (borrow_history.html) that displays
    all borrowing records from the database.
    """
    try:
        query = """
            SELECT
                br.id,
                br.client_id,
                c.Name AS client_name,
                br.book_isbn,
                b.Title AS book_title,
                br.borrow_date,
                br.due_date,
                br.return_date,
                br.status
            FROM borrow_records br
            JOIN clienttb c ON br.client_id = c.ID_Number
            JOIN booktb b ON br.book_isbn = b.ISBN
            ORDER BY br.id DESC
        """
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Prepare data for the template
        records = []
        for row in results:
            records.append({
                'id': row[0],
                'client_id': row[1],
                'client_name': row[2],
                'book_isbn': row[3],
                'book_title': row[4],
                'borrow_date': row[5],
                'due_date': row[6],
                'return_date': row[7],
                'status': row[8]
            })

        return render_template('borrow_history.html', borrow_records=records)
    except Exception as e:
        logging.error(f"Error fetching borrow history: {str(e)}")
        return f"Error fetching borrow history: {str(e)}"

@app.route("/all_borrow_history")
def all_borrow_history():
    """
    Fetches ALL records in borrow_records, joined with clienttb and booktb,
    showing everything ever borrowed (past or present).
    Renders them via a template or returns JSON. Modify as needed.
    """
    try:
        query = """
            SELECT
                br.id,
                br.client_id,
                c.Name AS client_name,
                br.book_isbn,
                b.Title AS book_title,
                br.borrow_date,
                br.due_date,
                br.return_date,
                br.status
            FROM borrow_records AS br
            JOIN clienttb AS c ON br.client_id = c.ID_Number
            JOIN booktb   AS b ON br.book_isbn = b.ISBN
            ORDER BY br.id DESC
        """
        cursor.execute(query)
        results = cursor.fetchall()

        records = []
        for row in results:
            records.append({
                'borrow_id'   : row[0],
                'client_id'   : row[1],
                'client_name' : row[2],
                'book_isbn'   : row[3],
                'book_title'  : row[4],
                'borrow_date' : str(row[5]),
                'due_date'    : str(row[6]),
                'return_date' : str(row[7]) if row[7] else None,
                'status'      : row[8]
            })

        # EXAMPLE: Render HTML template (uncomment if you have a corresponding template)
        # return render_template("all_borrow_history.html", borrow_records=records)

        # Or Return JSON (if you're retrieving data via JS)
        return jsonify({'success': True, 'borrow_records': records})

    except Exception as e:
        logging.error(f"Error fetching ALL borrow history: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/currently_borrowed")
def currently_borrowed():
    """
    Fetches only those borrow_records with a status of 'borrowed' (no return_date yet),
    letting you see which books are still checked out. Adjust the condition if
    you're using a different logic for "currently borrowed."
    """
    try:
        query = """
            SELECT
                br.id,
                br.client_id,
                c.Name AS client_name,
                br.book_isbn,
                b.Title AS book_title,
                br.borrow_date,
                br.due_date,
                br.return_date,
                br.status
            FROM borrow_records AS br
            JOIN clienttb AS c ON br.client_id = c.ID_Number
            JOIN booktb   AS b ON br.book_isbn = b.ISBN
            WHERE br.status = 'borrowed' 
              OR br.return_date IS NULL
            ORDER BY br.id DESC
        """
        cursor.execute(query)
        results = cursor.fetchall()

        records = []
        for row in results:
            records.append({
                'borrow_id'   : row[0],
                'client_id'   : row[1],
                'client_name' : row[2],
                'book_isbn'   : row[3],
                'book_title'  : row[4],
                'borrow_date' : str(row[5]),
                'due_date'    : str(row[6]),
                'return_date' : str(row[7]) if row[7] else None,
                'status'      : row[8]
            })

        # EXAMPLE: Render HTML template (uncomment if you have a corresponding template)
        # return render_template("currently_borrowed.html", borrow_records=records)

        # Or Return JSON (if you're retrieving data via JS)
        return jsonify({'success': True, 'borrow_records': records})

    except Exception as e:
        logging.error(f"Error fetching CURRENT borrowed books: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
if __name__ == '__main__':
    app.run(debug=True)