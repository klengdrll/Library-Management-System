from flask import Flask, render_template, request, redirect, jsonify,session
import logging
# from pyzbar.pyzbar import decode
from PIL import Image
import requests
import mysql.connector

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
    return render_template('Selection_Page.html')

import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/signup_page_student', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'POST':
        id_number = request.form.get('ID_Number')
        name = request.form.get('Name')
        department = request.form.get('Department')
        level = request.form.get('Level')
        course_strand = request.form.get('Course_Strand')
        email = request.form.get('Email')  # New input for Email
        gender = request.form.get('Gender')  # New input for Gender
        
        try:
            # Insert data into the ClientTB table
            insert_query = "INSERT INTO clienttb (ID_Number, Name, Department, Level, `Course/Strand`, Email, Gender) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            cursor.execute(insert_query, (id_number, name, department, level, course_strand, email, gender))
            db.commit()
            
            logging.info('Data inserted successfully into the database')
            return 'Data inserted successfully into the database'
        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return f'An error occurred: {str(e)}'

    return render_template('Signup_Page_Student.html')

@app.route('/admin_dashboard')
def dashboard():
    try:
        # Fetch data from the clienttb table
        cursor.execute("SELECT ID_Number, Name, Department, Level, `Course/Strand`, Email, Gender FROM clienttb")
        clients = cursor.fetchall()
        
        # Fetch data from the booktb table, including CoverImage
        cursor.execute("SELECT ISBN, Title, Author, Publisher, Genre, CoverImage FROM booktb")
        books = cursor.fetchall()

        if not clients:
            logging.warning('No data found in the clienttb table')

        if not books:
            logging.warning('No data found in the booktb table')
        
        # Process the client data
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

        # Process the book data
        book_data = []
        for book in books:
            book_data.append({
                'ISBN': book[0],
                'Title': book[1],
                'Author': book[2],
                'Publisher': book[3],
                'Genre': book[4],
                'CoverImage': book[5]
            })
        
        logging.info('Data fetched successfully from the database')
        return render_template('dashboard.html', clients=client_data, books=book_data)
    except Exception as e:
        logging.error(f'An error occurred: {str(e)}')
        return f'An error occurred: {str(e)}'
    
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
@app.route('/announcement', methods=['GET','POST' ])
def announcement():
    return render_template ('announcement.html')

@app.route('/info', methods=['GET', 'POST'])
def info():
    return render_template('info.html')

@app.route('/librarian', methods=['GET', 'POST'])
def librarian():
    return render_template('librarian.html')

@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        id_number = request.form.get('ID_Number')
        
        try:
            # Check if the ID_Number exists in the ClientTB table
            cursor.execute("SELECT ID_Number, Name FROM clienttb WHERE ID_Number = %s", (id_number,))
            student = cursor.fetchone()
            
            if student:
                session['student_id'] = student[0]
                session['student_name'] = student[1]
                logging.info('Student logged in successfully')
                return redirect('/student_dashboard')
            else:
                logging.warning('Invalid ID_Number')
                return 'Invalid ID_Number'
        except mysql.connector.Error as err:
            logging.error(f'Database error occurred: {err}')
            return f'Database error occurred: {err}'
        except Exception as e:
            logging.error(f'An error occurred: {str(e)}')
            return f'An error occurred: {str(e)}'
    return render_template('login_page.html')

@app.route('/student_dashboard')
def student_dashboard():
    if 'student_id' in session:
        student_id = session['student_id']
        student_name = session['student_name']
        
        # Placeholder for books borrowed
        books_borrowed = []  # Empty list for now
        
        return render_template('student_dashboard.html', student_name=student_name, student_id=student_id, books_borrowed=books_borrowed)
    else:
        return redirect('/login_page')

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
    
@app.route('/logout')
def logout():
    session.clear()
    logging.info('Student logged out successfully')
    return redirect('/login_page')

if __name__ == '__main__':
    app.run(debug=True)