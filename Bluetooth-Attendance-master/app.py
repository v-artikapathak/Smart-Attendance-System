from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask import Flask, request, jsonify
from celery_utils import make_celery
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from bleak import BleakScanner
import asyncio
from celery import shared_task
import mysql.connector
from mysql.connector import Error
from celery import Celery
import logging

from logging.handlers import RotatingFileHandler
from asgiref.sync import async_to_sync



# Configure logging settings
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG to capture all logs
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Standard format
    handlers=[  # Add handlers to output logs to both console and file
        logging.StreamHandler(),  # This will log to the console
        logging.FileHandler('attendance.log')  # This will log to a file named 'attendance.log'
    ]
)

# Create a logger object
logger = logging.getLogger(__name__)




app = Flask(__name__)

def make_celery(app):
    celery = Celery(app.import_name,
                    backend=app.config['result_backend'],
                    broker=app.config['broker_url'])
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        abstract = True
        def _call_(self, *args, **kwargs):
            with app.app_context():
                return super(ContextTask, self)._call_(*args, **kwargs)

    celery.Task = ContextTask
    return celery


app.config.update(
    result_backend='redis://localhost:6379/0',
    broker_url='redis://localhost:6379/0',
)

# Standardizing Celery settings to use new format



# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'VartikaGmail@23'
app.config['MYSQL_DB'] = 'blueatten'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# init MYSQL
mysql = MySQL(app)


# Config Celery
# app.config.update(
#     broker_url='amqp://localhost//',
#     result_backend='db+mysql://root:Nov%401224@localhost/blueatten',
# )

# Use new-style Celery configuration settings
app.config.update(
    result_backend='redis://localhost:6379/0',  # new-style
    broker_url='redis://localhost:6379/0',      # new-style
)

# Initialize Celery with the Flask app
celery = make_celery(app)
###############






# Configure logging




logger = logging.getLogger(__name__)

# @app.task(name='app.bluescan')
# def bluescan(macs, subj):
#     async def scan_device(mac_address):
#         try:
#             devices = await BleakScanner.discover(timeout=10.0)
#             for device in devices:
#                 if device.address == mac_address:
#                     return True
#             return False
#         except Exception as e:
#             logger.error(f"Error scanning for device {mac_address}: {str(e)}")
#             return False

#     async def scan_all_devices(macs, subj):
#         attendance_data = []
#         for mac in macs:
#             macadd = mac['macad']
#             found = await scan_device(macadd)
#             attend = 'present' if found else 'absent'
#             attendance_data.append((macadd, subj, attend))
        
#         return attendance_data

#     try:
#         logger.debug("Starting attendance scan...")
#         attendance_data = asyncio.run(scan_all_devices(macs, subj))

#         try:
#             connection = mysql.connector.connect(
#                 host='localhost',
#                 database='blueatten',
#                 user='root',
#                 password='Nov@1224'
#             )
            
#             if connection.is_connected():
#                 cursor = connection.cursor()
                
#                 for record in attendance_data:
#                     cursor.execute("INSERT INTO attendance(macad, subject, presabs) VALUES(%s, %s, %s)", record)
                
#                 connection.commit()
#                 logger.info("Attendance records inserted successfully")
        
#         except mysql.connector.Error as e:
#             logger.error(f"Error while connecting to MySQL: {str(e)}")
#             return 'Database connection error', str(e), None
        
#         finally:
#             if connection.is_connected():
#                 cursor.close()
#                 connection.close()
#                 logger.info("MySQL connection is closed")

#         return 'Done With The Attendance Check', None, None

#     except Exception as e:
#         logger.error(f"Error in bluescan task: {str(e)}")
#         return 'Error in Attendance Check', str(e), None


# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Student Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50), validators.DataRequired()])
    rollno = StringField('Rollno', [validators.Length(min=1, max=3), validators.DataRequired()])
    email = StringField('Email', [validators.Email(), validators.DataRequired()])
    macad = StringField('Macad', [validators.Length(max=17), validators.DataRequired()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# Student Register
@app.route('/registerStu', methods=['GET', 'POST'])
def registerStu():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        rollno = form.rollno.data
        macad = form.macad.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO students(name, email, rollno, macad, password) VALUES(%s, %s, %s, %s, %s)", (name, email, rollno, macad, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('loginStu'))
    return render_template('registerStu.html', form=form)


# Student login
@app.route('/loginStu', methods=['GET', 'POST'])
def loginStu():
    if request.method == 'POST':
        # Get Form Fields
        email = request.form['email']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by email
        result = cur.execute("SELECT * FROM students WHERE email = %s", [email])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            username = data['name']
            macadd = data['macad']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username
                session['student'] = True
                session['macaddress'] = macadd
                
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboardStu'))
            else:
                error = 'Invalid login'
                return render_template('loginStu.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Email not found'
            return render_template('loginStu.html', error=error)

    return render_template('loginStu.html')


# Professor Register Form Class
class ProfessorForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50), validators.DataRequired()])
    email = StringField('Email', [validators.Email(), validators.DataRequired()])
    subject = StringField('Subject', [validators.Length(min=1, max=17), validators.DataRequired()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# Professor Register
@app.route('/registerPro', methods=['GET', 'POST'])
def registerPro():
    form = ProfessorForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        subject = form.subject.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO professors(name, email, subject, password) VALUES(%s, %s, %s, %s)", (name, email, subject, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('loginPro'))
    return render_template('registerPro.html', form=form)


# Professor login
@app.route('/loginPro', methods=['GET', 'POST'])
def loginPro():
    if request.method == 'POST':
        # Get Form Fields
        email = request.form['email']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by email
        result = cur.execute("SELECT * FROM professors WHERE email = %s", [email])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']
            username = data['name']
            sub = data['subject']
            
            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username
                session['student'] = False
                session['subject'] = sub

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboardPro'))
            else:
                error = 'Invalid login'
                return render_template('loginPro.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Email not found'
            return render_template('loginPro.html', error=error)

    return render_template('loginPro.html')


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('index'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('index'))

# Dashboard Student
@app.route('/dashboardStu')
@is_logged_in
def dashboardStu():
    macadress = session['macaddress']
    # Create cursor
    cur = mysql.connection.cursor()

    # Get attendance
    result = cur.execute("SELECT * FROM attendance WHERE macad = %s", [macadress])

    attends = cur.fetchall()

    if result > 0:
        return render_template('dashboardStu.html', attends=attends)
    else:
        msg = 'No Attendance Found'
        return render_template('dashboardStu.html', msg=msg)
    # Close connection
    cur.close()

# Dashboard Professors
@app.route('/dashboardPro')
@is_logged_in
def dashboardPro():
    subject = session['subject']
    # Create cursor
    cur = mysql.connection.cursor()

    # Get attendance
    result = cur.execute("SELECT name, attendance.id, subject, presabs, class_date FROM students, attendance WHERE attendance.macad = students.macad and subject = %s", [subject])

    attends = cur.fetchall()

    if result > 0:
        return render_template('dashboardPro.html', attends=attends)
    else:
        msg = 'No Attendance Found'
        return render_template('dashboardPro.html', msg=msg)
    # Close connection
    cur.close()

# Check Attendance
@app.route('/check_attendance')
@is_logged_in
def check_attendance():
    subject = session['subject']  # Get subject from session
    
    # Create cursor to get MAC addresses from the database
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT macad FROM students")
    macads = cur.fetchall()  # Fetch all MAC addresses

    # If records exist, format mac addresses and call the task
    if result > 0:
        mac_list = [{'macad': mac['macad']} for mac in macads]

        # Call the Celery task asynchronously
        bluescan.delay(mac_list, subject)
        logger.info("Started attendance scan for subject: %s", subject)

        # Show scan progress page
        return render_template('scan_prog.html')
    else:
        # No MAC addresses found, return a message
        msg = 'No Records Found'
        logger.warning("No MAC addresses found for subject: %s", subject)
        return render_template('dashboardPro.html', msg=msg)

    # Close cursor
    cur.close()

# @app.route('/check_attendance')
# @is_logged_in
# def check_attendance():
#     sub = session['subject']
    
#     # Create cursor
#     cur = mysql.connection.cursor()
    
#     # Get mac addresses
#     result = cur.execute("SELECT macad FROM students")
    
#     macads = cur.fetchall()
#     mac_list = [{'macad': mac['macad']} for mac in macads]

#     if result > 0:
#         bluescan.delay(macads, sub)
#         return render_template('scan_prog.html')
#     else:
#         msg = 'No Records Found'
#         return render_template('dashboardPro.html', msg=msg)
#     # Close connection
#     cur.close()

# Celery Task
# from asgiref.sync import async_to_sync

# @celery.task(name='app.bluescan')
# def bluescan(macs, subj):
#     async def scan_device(mac_address):
#         devices = await BleakScanner.discover()
#         for device in devices:
#             if device.address == mac_address:
#                 return True
#         return False

#     async def scan_all_devices(macs, subj):
#         for mac in macs:
#             macadd = mac['macad']
#             found = await scan_device(macadd)
#             attend = 'present' if found else 'absent'
            
#             # Create cursor
#             cur = mysql.connection.cursor()
            
#             # Execute query
#             cur.execute("INSERT INTO attendance(macad, subject, presabs) VALUES(%s, %s, %s)", (macadd, subj, attend))
            
#             # Commit to DB
#             mysql.connection.commit()
            
#             # Close Connection
#             cur.close()

#     return async_to_sync(scan_all_devices)(macs, subj)
@celery.task(name='app.bluescan')
def bluescan(macs, subj):
    logger.debug(f"Received MAC addresses: {macs}")
    logger.debug(f"Subject: {subj}")
    async def scan_device(mac_address):
        try:
            logger.debug(f"Scanning for MAC address: {mac_address}")
            devices = await BleakScanner.discover(timeout=20.0)  # Increased timeout to 20 seconds
            for device in devices:
                logger.debug(f"Found device: {device.address} - {device.name}")
                if device.address == mac_address:
                    logger.debug(f"Found matching device: {device.address}")
                    return True, None, None
            logger.debug(f"No matching device found for MAC address: {mac_address}")
            return False, None, None
        except Exception as e:
            logger.error(f"Error scanning for device {mac_address}: {str(e)}")
            return False, None, None

    async def scan_all_devices(macs, subj):
        seen_macs = set()
        attendance_data = []

        for mac in macs:
            macadd = mac['macad']

            if macadd in seen_macs:
                logger.debug(f"Skipping duplicate MAC address: {macadd}")
                continue

            seen_macs.add(macadd)

            found, _, _ = await scan_device(macadd)
            attend = 'present' if found else 'absent'
            logger.debug(f"MAC: {macadd}, Subject: {subj}, Attendance: {attend}")
            attendance_data.append((macadd, subj, attend))

        return attendance_data, None, None

    try:
        logger.debug("Starting attendance scan...")
        attendance_data, _, _ = asyncio.run(scan_all_devices(macs, subj))

        # Database operations
        cursor = mysql.connection.cursor()

        for record in attendance_data:
            macadd, subj, attend = record
            cursor.execute("SELECT * FROM attendance WHERE macad = %s AND subject = %s", (macadd, subj))
            existing_record = cursor.fetchone()

            if not existing_record:
                cursor.execute("INSERT INTO attendance(macad, subject, presabs) VALUES(%s, %s, %s)", (macadd, subj, attend))
                logger.debug(f"Inserted record: MAC: {macadd}, Subject: {subj}, Attendance: {attend}")
            else:
                logger.debug(f"Record already exists for MAC: {macadd}, Subject: {subj}")

        mysql.connection.commit()
        cursor.close()
        logger.info("Attendance records inserted successfully")

    except Error as e:
        logger.error(f"Error while connecting to MySQL: {str(e)}")
        return 'Database connection error', str(e), None

    except Exception as e:
        logger.error(f"Error in bluescan task: {str(e)}")
        return 'Error in Attendance Check', str(e), None

    return 'Done With The Attendance Check', None, None



# Delete Attendance
@app.route('/delete_attendance/<string:id>', methods=['POST'])
@is_logged_in
def delete_attendance(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM attendance WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    # Close connection
    cur.close()

    flash('Attendance Deleted', 'success')

    return redirect(url_for('dashboardPro'))





if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True, host='0.0.0.0')
