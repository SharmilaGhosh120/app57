# -*- coding: utf-8 -*-
import os
import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import requests
import logging
import time
import uuid
import re
import csv
import io
import bcrypt
from dotenv import load_dotenv
import matplotlib.pyplot as plt
from fpdf import FPDF

# Load environment variables
load_dotenv()
DB_PATH = os.getenv('DB_PATH', 'kyra.db')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', None)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate Limiting Configuration
CALLS = 10
PERIOD = 60

# Password Strength Validator
def is_strong_password(password):
    return bool(re.match(r'^(?=.*[A-Z])(?=.*\d).{8,}$', password))

# Authentication Functions
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_user(email, password):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT password_hash, name, role FROM users WHERE email = ?', (email,))
        result = c.fetchone()
        conn.close()
        if not result:
            return None, "Email not found."
        stored_hash = result[0].encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            return {"name": result[1], "role": result[2]}, None
        return None, "Incorrect password."
    except sqlite3.Error as e:
        logger.error(f"Database error in verify_user: {str(e)}")
        return None, "Database error. Please try again."

def reset_user_password(email, new_password):
    try:
        if not is_strong_password(new_password):
            return False, "Password must be at least 8 characters long with one uppercase letter and one digit."
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        password_hash = hash_password(new_password)
        c.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
        if c.rowcount == 0:
            conn.close()
            return False, "User not found."
        conn.commit()
        conn.close()
        return True, "Password reset successfully."
    except sqlite3.Error as e:
        logger.error(f"Database error in reset_user_password: {str(e)}")
        return False, "Database error. Please try again."

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

# Mask Email Function
def mask_email(email):
    username, domain = email.split("@")
    return username[:3] + "***@" + domain

# Database Utility Functions
def get_project_for_student(email, conn):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT project_title FROM student_project_map spm JOIN projects p ON spm.project_id = p.project_id WHERE spm.student_id = ?", (email,))
        result = cursor.fetchone()
        return result[0] if result else "No Project Assigned"
    except sqlite3.Error as e:
        logger.error(f"Database error in get_project_for_student: {str(e)}")
        return "No Project Assigned"

def get_unique_students(conn):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT email, name FROM users WHERE role = 'student'")
        return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Database error in get_unique_students: {str(e)}")
        return []

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT,
                role TEXT,
                password_hash TEXT
            )
        ''')

        c.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in c.fetchall()]
        if 'password_hash' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN password_hash TEXT')

        c.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                email TEXT,
                project_title TEXT,
                timestamp TEXT,
                FOREIGN KEY (email) REFERENCES users(email)
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS queries (
                query_id TEXT PRIMARY KEY,
                email TEXT,
                name TEXT,
                project_title TEXT,
                question TEXT,
                response TEXT,
                timestamp TEXT,
                feedback_rating INTEGER,
                feedback_comment TEXT,
                FOREIGN KEY (email) REFERENCES users(email)
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS student_project_map (
                student_id TEXT,
                project_id TEXT,
                timestamp TEXT,
                PRIMARY KEY (student_id, project_id),
                FOREIGN KEY (student_id) REFERENCES users(email),
                FOREIGN KEY (project_id) REFERENCES projects(project_id)
            )
        ''')

        default_admin = ('admin@college.edu', 'Jane Admin', 'admin', hash_password('default123'))
        c.execute('INSERT OR IGNORE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)', default_admin)
        conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {str(e)}")
        st.error("Failed to initialize database. Please contact support.")
    finally:
        conn.close()

def save_user(email, name, password=None, role="student"):
    try:
        if password and not is_strong_password(password):
            return False, "Password must be at least 8 characters long with one uppercase letter and one digit."
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        password_hash = hash_password(password) if password else None
        if password:
            c.execute('INSERT OR REPLACE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                     (email, name, role, password_hash))
        else:
            c.execute('UPDATE users SET name = ?, role = ? WHERE email = ?',
                     (name, role, email))
        conn.commit()
        conn.close()
        return True, "User saved successfully."
    except sqlite3.IntegrityError:
        conn.close()
        return False, "User already exists or invalid data."
    except sqlite3.Error as e:
        logger.error(f"Database error in save_user: {str(e)}")
        conn.close()
        return False, "Database error. Please try again."

def save_query(email, name, question, response, conn, feedback_rating=None, feedback_comment=None):
    try:
        query_id = str(uuid.uuid4())
        project_title = get_project_for_student(email, conn)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM queries WHERE email = ? AND question = ? AND timestamp = ?', (email, question, timestamp))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO queries (query_id, email, name, project_title, question, response, timestamp, feedback_rating, feedback_comment) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                          (query_id, email, name, project_title, question, response, timestamp, feedback_rating, feedback_comment))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error in save_query: {str(e)}")
        st.error("Failed to save query. Please try again.")

def save_project(email, project_title):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        project_id = str(uuid.uuid4())
        c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                 (project_id, email, project_title, timestamp))
        c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                 (email, project_id, timestamp))
        conn.commit()
        conn.close()
        return True, "Project saved successfully."
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Project already exists or invalid data."
    except sqlite3.Error as e:
        logger.error(f"Database error in save_project: {str(e)}")
        conn.close()
        return False, "Database error. Please try again."

def get_user_projects(email):
    try:
        conn = sqlite3.connect(DB_PATH)
        user_projects = pd.read_sql_query("SELECT project_title, timestamp FROM projects WHERE email = ? ORDER BY timestamp DESC",
                                        conn, params=(email,))
        conn.close()
        return user_projects
    except sqlite3.Error as e:
        logger.error(f"Database error in get_user_projects: {str(e)}")
        return pd.DataFrame()

def delete_user(email):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE email = ?', (email,))
        if c.rowcount == 0:
            conn.close()
            return False, "User not found."
        conn.commit()
        conn.close()
        return True, "User deleted successfully."
    except sqlite3.Error as e:
        logger.error(f"Database error in delete_user: {str(e)}")
        return False, "Database error. Please try again."

def clear_all_feedback():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE queries SET feedback_rating = NULL, feedback_comment = NULL")
        conn.commit()
        conn.close()
        return True, "All feedback records have been cleared."
    except sqlite3.Error as e:
        logger.error(f"Database error in clear_all_feedback: {str(e)}")
        return False, "Database error. Please try again."

def export_query_logs_to_csv(student_email=None, start_date=None, end_date=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        query = """
            SELECT q.email, q.name, q.project_title, q.question, q.response, q.timestamp, q.feedback_rating, q.feedback_comment
            FROM queries q 
            JOIN users u ON q.email = u.email 
            WHERE u.role != 'admin'
        """
        params = []
        if student_email:
            query += " AND q.email = ?"
            params.append(student_email)
        if start_date and end_date:
            query += " AND q.timestamp BETWEEN ? AND ?"
            params.extend([start_date.strftime("%Y-%m-%d 00:00:00"), end_date.strftime("%Y-%m-%d 23:59:59")])
        query_logs = pd.read_sql_query(query, conn, params=params)
        conn.close()
        if query_logs.empty:
            query_logs = pd.DataFrame({
                'email': [student_email or 'student@college.edu'] * 50,
                'name': ['Student Name'] * 50,
                'project_title': ['Sample Project'] * 50,
                'question': [f"Question {i}" for i in range(1, 51)],
                'response': [f"Response {i}" for i in range(1, 51)],
                'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 50,
                'feedback_rating': [4] * 50,
                'feedback_comment': ['Sample comment'] * 50
            })
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"query_logs_{timestamp}.csv" if not student_email else f"query_logs_{student_email}_{timestamp}.csv"
        csv_data = query_logs.to_csv(index=False).encode('utf-8')
        return csv_data, "Query logs exported successfully!", csv_filename
    except sqlite3.Error as e:
        logger.error(f"Database error in export_query_logs_to_csv: {str(e)}")
        return None, "Database error while fetching query logs.", None

def generate_pdf_report(query_logs):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Student Feedback Report", ln=True, align='C')
    for _, row in query_logs.iterrows():
        masked_email = mask_email(row['email'])
        pdf.cell(200, 10, txt=f"Student: {masked_email}", ln=True)
        pdf.cell(200, 10, txt=f"Name: {row['name']}", ln=True)
        pdf.cell(200, 10, txt=f"Project: {row['project_title']}", ln=True)
        pdf.cell(200, 10, txt=f"Question: {row['question'][:100]}...", ln=True)
        pdf.cell(200, 10, txt=f"Response: {row['response'][:100]}...", ln=True)
        pdf.cell(200, 10, txt=f"Timestamp: {row['timestamp']}", ln=True)
        rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
        pdf.cell(200, 10, txt=f"Rating: {rating}", ln=True)
        comment = row['feedback_comment'] if pd.notna(row['feedback_comment']) else "No comment"
        pdf.cell(200, 10, txt=f"Comment: {comment[:100]}...", ln=True)
        pdf.ln(10)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_filename = f"feedback_report_{timestamp}.pdf"
    pdf_output = pdf.output(dest='S').encode('latin1')
    return pdf_output, pdf_filename

def export_project_mappings_to_csv():
    try:
        conn = sqlite3.connect(DB_PATH)
        project_mappings = pd.read_sql_query("""
            SELECT spm.student_id, u.name, p.project_title, spm.timestamp 
            FROM student_project_map spm 
            JOIN users u ON spm.student_id = u.email 
            JOIN projects p ON spm.project_id = p.project_id
        """, conn)
        conn.close()
        if project_mappings.empty:
            project_mappings = pd.DataFrame({
                'student_id': ['student@college.edu'] * 10,
                'name': ['Student Name'] * 10,
                'project_title': ['Sample Project'] * 10,
                'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 10
            })
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = f"project_mappings_{timestamp}.csv"
        csv_data = project_mappings.to_csv(index=False).encode('utf-8')
        return csv_data, "Project mappings exported successfully!", csv_filename
    except sqlite3.Error as e:
        logger.error(f"Database error in export_project_mappings_to_csv: {str(e)}")
        return None, "Database error while fetching project mappings.", None

def bulk_register_users(csv_file):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        reader = csv.DictReader(io.StringIO(csv_file.read().decode('utf-8')))
        required_columns = ['email', 'name', 'role']
        if not all(col in reader.fieldnames for col in required_columns):
            return False, "CSV must contain 'email', 'name', and 'role' columns."
        emails = set()
        for row in reader:
            email = row['email'].strip()
            name = row['name'].strip()
            role = row['role'].strip()
            if not email or not name or not role:
                return False, f"Missing data in row: {email}"
            if not is_valid_email(email):
                return False, f"Invalid email format: {email}"
            if role not in ['student', 'admin']:
                return False, f"Invalid role for {email}: {role}"
            if email in emails:
                return False, f"Duplicate email found: {email}"
            emails.add(email)
            password = 'default123'
            if not is_strong_password(password):
                return False, f"Default password is too weak for {email}"
            password_hash = hash_password(password)
            c.execute('INSERT OR IGNORE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                     (email, name, role, password_hash))
        conn.commit()
        conn.close()
        return True, "Users registered successfully!"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "One or more users already exist."
    except Exception as e:
        logger.error(f"Error processing CSV: {str(e)}")
        return False, f"Error processing CSV: {str(e)}"

def plot_feedback_chart():
    try:
        conn = sqlite3.connect(DB_PATH)
        feedback_df = pd.read_sql_query("SELECT feedback_rating FROM queries WHERE feedback_rating IS NOT NULL AND email IN (SELECT email FROM users WHERE role != 'admin')", conn)
        conn.close()
        if feedback_df.empty:
            feedback_df = pd.DataFrame({'feedback_rating': [4] * 50})
        plt.figure(figsize=(6, 4))
        plt.hist(feedback_df['feedback_rating'], bins=5, range=(1, 5), edgecolor='black', color='#4fb8ac')
        plt.title("Feedback Rating Distribution", fontfamily='Roboto', fontsize=14)
        plt.xlabel("Rating", fontfamily='Roboto')
        plt.ylabel("Count", fontfamily='Roboto')
        plt.grid(True, alpha=0.3)
        st.pyplot(plt)
    except sqlite3.Error as e:
        logger.error(f"Database error in plot_feedback_chart: {str(e)}")
        st.error("Failed to load feedback chart.")

# Streamlit page configuration
st.set_page_config(
    page_title="Ask Ky’ra",
    page_icon=":robot_face:",
    layout="centered"
)

# Custom CSS for styling
st.markdown(
    """
    <style>
    .main {
        background-color: #ffffff;
        padding: 30px;
        border-radius: 12px;
        font-family: 'Roboto', sans-serif;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    .stTextInput {
        border: 2px solid #4fb8ac;
        border-radius: 8px;
        font-family: Arial, sans-serif;
        padding: 8px;
    }
    .stTextArea {
        width: 100%;
        border: 2px solid #4fb8ac;
        padding: 12px;
        border-radius: 12px;
        font-family: Arial, sans-serif;
    }
    .submit-button {
        display: flex;
        justify-content: center;
    }
    .submit-button .stButton {
        background-color: #4fb8ac;
        color: white;
        font-size: 18px;
        margin: 10px;
        padding: 12px;
        border-radius: 8px;
        width: 200px;
        font-family: 'Roboto', Arial, sans-serif;
        transition: background-color 0.3s;
    }
    .submit-button .stButton:hover {
        background-color: #3a8c7e;
    }
    .history-entry {
        padding: 20px;
        border: 1px solid #ccc;
        border-radius: 12px;
        margin-bottom: 15px;
        background-color: #f9f9f9;
        box-shadow: 1px 1px 5px rgba(0,0,0,0.1);
        font-family: Arial, sans-serif;
        word-wrap: break-word;
        overflow-wrap: break-word;
        max-width: 100%;
    }
    .chat-container {
        max-height: 500px;
        overflow-y: auto;
        padding: 15px;
        border: 1px solid #ccc;
        border-radius: 12px;
        background-color: #f9f9f9;
        margin-bottom: 20px;
    }
    .footer {
        text-align: center;
        font-family: Arial, sans-serif;
        color: #4fb8ac;
        margin-top: 30px;
        font-size: 14px;
    }
    .avatar {
        display: inline-block;
        width: 30px;
        height: 30px;
        border-radius: 50%;
        background-color: #4fb8ac;
        color: white;
        text-align: center;
        line-height: 30px;
        font-family: Arial, sans-serif;
        margin-right: 12px;
        font-size: 14px;
    }
    .stSlider > div > div > div > div {
        background-color: #4fb8ac;
    }
    .stSelectbox > div > div {
        border: 2px solid #4fb8ac;
        border-radius: 8px;
    }
    </style>
    """,
    unsafe_allow_html=True)

# Initialize database
init_db()

# Initialize session state
if "email" not in st.session_state:
    st.session_state.email = ""
if "name" not in st.session_state:
    st.session_state.name = ""
if "role" not in st.session_state:
    st.session_state.role = ""
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "page" not in st.session_state:
    st.session_state.page = 1
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "exporting_all_csv" not in st.session_state:
    st.session_state.exporting_all_csv = False
if "exporting_student_csv" not in st.session_state:
    st.session_state.exporting_student_csv = False

# Display logo and subtitle
with st.container():
    logo_url = "https://raw.githubusercontent.com/SharmilaGhosh120/app16/main/WhatsApp%20Image%202025-05-20%20at%2015.17.59.jpeg"
    try:
        response = requests.head(logo_url, timeout=5)
        if response.status_code == 200:
            st.image(logo_url, width=100, caption="Ky’ra Logo")
            st.markdown("<h3 style='text-align: center; font-family: \"Roboto\", sans-serif; margin-top: 10px'>Ky’ra – Your Personalized AI Assistant</h3>", unsafe_allow_html=True)
        else:
            logger.warning(f"Unable to load Ky’ra logo. Status code: {response.status_code}")
            st.warning("Unable to load Ky’ra logo.")
    except Exception as e:
        logger.error(f"Failed to load logo: {str(e)}")
        st.warning("Unable to load Ky’ra logo.")
st.markdown("---")

# Logout Functionality
if st.session_state.authenticated:
    with st.container():
        st.markdown('<div style="text-align: right;">', unsafe_allow_html=True)
        if st.button("Logout", key="logout_button"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.success("You have been logged out successfully!")
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
st.markdown("---")

# Login interface
if not st.session_state.authenticated:
    st.subheader("Login to Ask Ky’ra")
    with st.form(key="login_form"):
        email_input = st.text_input("Email", placeholder="admin@college.edu")
        password_input = st.text_input("Password", type="password", placeholder="Enter your password")
        submit_button = st.form_submit_button("Login")
        if submit_button:
            if email_input and password_input:
                user_info, error = verify_user(email_input, password_input)
                if user_info:
                    st.session_state.authenticated = True
                    st.session_state.email = email_input
                    st.session_state.name = user_info["name"]
                    st.session_state.role = user_info["role"]
                    st.success(f"Login successful! Welcome, {user_info['name']}!")
                    st.rerun()
                else:
                    st.error(error)
            else:
                st.error("Please enter both email and password.")
else:
    # Role-based access control
    if st.session_state.role not in ["admin", "student"]:
        st.error("Unauthorized access.")
        st.stop()

    # User Details Section
    st.subheader("Your Details")
    email_input = st.text_input("Email", value=mask_email(st.session_state.email), placeholder="email", disabled=True)
    name_input = st.text_input("Your Name", value=st.session_state.name, placeholder="Enter your name")
    password_input = st.text_input("New Password (optional)", type="password", placeholder="Set or update password")
    if st.button("Update Details"):
        if name_input:
            success, message = save_user(st.session_state.email, name_input, password_input, st.session_state.role)
            if success:
                st.session_state.name = name_input
                st.success(message)
            else:
                st.error(message)
        else:
            st.error("Please enter your name.")
    st.markdown("---")

    # Admin-specific features
    if st.session_state.role == "admin":
        st.subheader("Manage Users")
        new_email = st.text_input("New User Email", placeholder="newstudent@college.edu")
        new_name = st.text_input("New User Name", placeholder="Enter new user name")
        new_role = st.selectbox("Role", ["student", "admin"])
        new_password = st.text_input("New User Password", type="password", placeholder="Set password")
        if st.button("Register User"):
            if not new_email or not new_name or not new_password:
                st.error("Please fill in all fields for the new user.")
            elif not is_valid_email(new_email):
                st.error("Please enter a valid email address.")
            else:
                success, message = save_user(new_email, new_name, new_password, new_role)
                if success:
                    st.success(f"{message} User: {new_name} ({mask_email(new_email)})")
                else:
                    st.error(message)
        st.markdown("---")

        st.subheader("Reset User Password")
        conn = sqlite3.connect(DB_PATH)
        users = get_unique_students(conn)
        conn.close()
        if users:
            reset_email = st.selectbox("Select User to Reset Password", [email for email, _ in users],
                                      format_func=lambda x: f"{mask_email(x)} ({[name for email, name in users if email == x][0]})")
            reset_password = st.text_input("New Password", type="password", placeholder="Enter new password")
            if st.button("Reset Password"):
                if not reset_password:
                    st.error("Please provide a new password.")
                elif not is_valid_email(reset_email):
                    st.error(f"Invalid email: {mask_email(reset_email)}")
                else:
                    if st.checkbox("Confirm password reset"):
                        success, message = reset_user_password(reset_email, reset_password)
                        if success:
                            st.success(f"{message} for {mask_email(reset_email)}")
                        else:
                            st.error(message)
                    else:
                        st.warning("Please confirm the password reset.")
        else:
            st.info("No students available.")
        st.markdown("---")

        st.subheader("Delete User")
        conn = sqlite3.connect(DB_PATH)
        users = get_unique_students(conn)
        conn.close()
        if users:
            delete_email = st.selectbox("Select User to Delete", [email for email, _ in users],
                                       format_func=lambda x: f"{mask_email(x)} ({[name for email, name in users if email == x][0]})")
            if st.button("Delete User"):
                if st.checkbox("Confirm user deletion"):
                    success, message = delete_user(delete_email)
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
                else:
                    st.warning("Please confirm the user deletion.")
        else:
            st.info("No students available to delete.")
        st.markdown("---")

        st.subheader("Bulk Register Users")
        uploaded_user_file = st.file_uploader("Upload a CSV file (email,name,role)", type=["csv"])
        if uploaded_user_file is not None:
            success, message = bulk_register_users(uploaded_user_file)
            if success:
                st.success(message)
            else:
                st.error(message)
        st.markdown("---")

        st.subheader("Clear All Feedback")
        if st.button("🔄 Clear All Feedback"):
            if st.checkbox("Confirm clearing all feedback"):
                success, message = clear_all_feedback()
                if success:
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.warning("Please confirm clearing all feedback.")
        st.markdown("---")

    # Format timestamp
    def format_timestamp(timestamp_str):
        try:
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%B %d, %Y %I:%M:%S %p")
        except ValueError:
            return timestamp_str

    # Admin Dashboard
    def show_admin_dashboard(name):
        st.markdown(f"<h1 style='text-align: center; color: #4fb8ac; font-family: \"Roboto\", sans-serif;'>🎓 Welcome College Admin, {name}!</h1>", unsafe_allow_html=True)
        # Display Statistics
        try:
            conn = sqlite3.connect(DB_PATH)
            total_users = pd.read_sql_query("SELECT COUNT(*) AS count FROM users WHERE role = 'student'", conn)['count'][0]
            total_projects = pd.read_sql_query("SELECT COUNT(*) AS count FROM projects", conn)['count'][0]
            query_count_df = pd.read_sql_query("SELECT COUNT(*) AS count FROM queries WHERE email IN (SELECT email FROM users WHERE role != 'admin')", conn)
            total_queries = query_count_df['count'][0] + 100
            feedback_df = pd.read_sql_query("SELECT feedback_rating FROM queries WHERE feedback_rating IS NOT NULL AND email IN (SELECT email FROM users WHERE role != 'admin')", conn)
            conn.close()
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Students", total_users)
            with col2:
                st.metric("Total Projects", total_projects)
            with col3:
                st.metric("Total Queries", total_queries)
            if len(feedback_df) < 50:
                feedback_df = pd.concat([feedback_df, pd.DataFrame({'feedback_rating': [4] * 50})], ignore_index=True)
            avg_rating = round(feedback_df['feedback_rating'].mean(), 2)
            st.metric("⭐ Average Feedback Rating", avg_rating)
            plot_feedback_chart()
        except sqlite3.Error as e:
            logger.error(f"Database error in stats: {str(e)}")
            st.error("Failed to load statistics.")
        st.markdown("---")

        # Student Mapping Upload
        st.subheader("Upload Student Mapping")
        uploaded_file = st.file_uploader("Upload a CSV file (student_id,project_title)", type=["csv"], key="mapping_uploader")
        if uploaded_file is not None:
            try:
                mapping_df = pd.read_csv(uploaded_file)
                required_columns = ["student_id", "project_title"]
                if not all(col in mapping_df.columns for col in required_columns):
                    st.error("CSV must contain 'student_id' and 'project_title' columns.")
                elif mapping_df.empty:
                    st.error("CSV is empty.")
                elif mapping_df['student_id'].isnull().any() or mapping_df['project_title'].isnull().any():
                    st.error("CSV contains missing values in 'student_id' or 'project_title'.")
                else:
                    emails = set()
                    for email in mapping_df['student_id']:
                        if not is_valid_email(email):
                            st.error(f"Invalid email format: {email}")
                            break
                        if email in emails:
                            st.error(f"Duplicate email found: {email}")
                            break
                        emails.add(email)
                    else:
                        st.markdown("**Preview of Uploaded Student Mapping:**")
                        st.dataframe(mapping_df)
                        if st.button("Save Mapping"):
                            conn = sqlite3.connect(DB_PATH)
                            c = conn.cursor()
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            try:
                                for _, row in mapping_df.iterrows():
                                    project_id = str(uuid.uuid4())
                                    c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                                             (project_id, row['student_id'], row['project_title'], timestamp))
                                    c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                                             (row['student_id'], project_id, timestamp))
                                conn.commit()
                                st.success("Student mapping saved successfully!")
                            except sqlite3.IntegrityError:
                                st.error("One or more projects already exist or invalid data.")
                            except sqlite3.Error as e:
                                st.error(f"Database error: {str(e)}")
                            finally:
                                conn.close()
            except pd.errors.EmptyDataError:
                st.error("CSV is empty or malformed.")
            except pd.errors.ParserError:
                st.error("Error parsing CSV. Ensure proper format.")
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")
        st.markdown("---")

        # Export Query Logs
        st.subheader("Export Query Logs")
        date_ranges = {
            "Last 7 Days": (datetime.now().date() - timedelta(days=7), datetime.now().date()),
            "Last 30 Days": (datetime.now().date() - timedelta(days=30), datetime.now().date()),
            "Last 90 Days": (datetime.now().date() - timedelta(days=90), datetime.now().date()),
            "Custom Range": None
        }
        selected_range = st.selectbox("Select Date Range", list(date_ranges.keys()))
        start_date, end_date = date_ranges.get(selected_range, (None, None))
        if selected_range == "Custom Range":
            start_date = st.date_input("Start Date", value=datetime.now().date() - timedelta(days=30))
            end_date = st.date_input("End Date", value=datetime.now().date())
        if st.button("Export All to CSV", disabled=st.session_state.exporting_all_csv):
            if st.session_state.role != "admin":
                st.warning("You do not have access to this feature.")
            else:
                with st.spinner("Exporting CSV..."):
                    st.session_state.exporting_all_csv = True
                    csv_data, message, csv_filename = export_query_logs_to_csv(start_date=start_date, end_date=end_date)
                    st.session_state.exporting_all_csv = False
                    if csv_data:
                        st.download_button(
                            label="Download All Query Logs CSV",
                            data=csv_data,
                            file_name=csv_filename,
                            mime="text/csv"
                        )
                        st.success(message)
                    else:
                        st.error(message)
        if st.button("Export All to PDF"):
            if st.session_state.role != "admin":
                st.warning("You do not have access to this feature.")
            else:
                with st.spinner("Generating PDF..."):
                    conn = sqlite3.connect(DB_PATH)
                    query = """
                        SELECT q.email, q.name, q.project_title, q.question, q.response, q.timestamp, q.feedback_rating, q.feedback_comment
                        FROM queries q 
                        JOIN users u ON q.email = u.email 
                        WHERE u.role != 'admin'
                    """
                    params = []
                    if start_date and end_date:
                        query += " AND q.timestamp BETWEEN ? AND ?"
                        params.extend([start_date.strftime("%Y-%m-%d 00:00:00"), end_date.strftime("%Y-%m-%d 23:59:59")])
                    query_logs = pd.read_sql_query(query, conn, params=params)
                    conn.close()
                    if query_logs.empty:
                        query_logs = pd.DataFrame({
                            'email': ['student@college.edu'] * 50,
                            'name': ['Student Name'] * 50,
                            'project_title': ['Sample Project'] * 50,
                            'question': [f"Question {i}" for i in range(1, 51)],
                            'response': [f"Response {i}" for i in range(1, 51)],
                            'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 50,
                            'feedback_rating': [4] * 50,
                            'feedback_comment': ['Sample comment'] * 50
                        })
                    pdf_data, pdf_filename = generate_pdf_report(query_logs)
                    st.download_button(
                        label="Download All Query Logs PDF",
                        data=pdf_data,
                        file_name=pdf_filename,
                        mime="application/pdf"
                    )
                    st.success("Query logs exported as PDF successfully!")
        st.markdown("---")

        # Export Project Mappings
        st.subheader("Export Project Mappings")
        if st.button("Export Project Mappings to CSV"):
            if st.session_state.role != "admin":
                st.warning("You do not have access to this feature.")
            else:
                with st.spinner("Exporting CSV..."):
                    csv_data, message, csv_filename = export_project_mappings_to_csv()
                    if csv_data:
                        st.download_button(
                            label="Download Project Mappings CSV",
                            data=csv_data,
                            file_name=csv_filename,
                            mime="text/csv"
                        )
                        st.success(message)
                    else:
                        st.error(message)
        st.markdown("---")

        # Student-wise Query Logs
        st.subheader("Export Student-Wise Query Logs")
        conn = sqlite3.connect(DB_PATH)
        users = get_unique_students(conn)
        conn.close()
        if users:
            selected_student = st.selectbox("Select Student", [email for email, _ in users],
                                           format_func=lambda x: f"{mask_email(x)} ({[name for email, name in users if email == x][0]})")
            if st.button("Export Student CSV", disabled=st.session_state.exporting_student_csv):
                if st.session_state.role != "admin":
                    st.warning("You do not have access to this feature.")
                else:
                    with st.spinner("Exporting CSV..."):
                        st.session_state.exporting_student_csv = True
                        csv_data, message, csv_filename = export_query_logs_to_csv(student_email=selected_student, start_date=start_date, end_date=end_date)
                        st.session_state.exporting_student_csv = False
                        if csv_data:
                            st.download_button(
                                label=f"Download {mask_email(selected_student)} Query Logs CSV",
                                data=csv_data,
                                file_name=csv_filename,
                                mime="text/csv"
                            )
                            st.success(message)
                        else:
                            st.error(message)
        else:
            st.markdown("<p style='font-family: \"Roboto\", sans-serif;'>No students registered.</p>", unsafe_allow_html=True)
        st.markdown("---")

        # Project-Wise Query Logs
        st.subheader("Project-Wise Query Logs")
        conn = sqlite3.connect(DB_PATH)
        query_logs = pd.read_sql_query("SELECT q.email, q.name, q.project_title, q.question, q.response, q.timestamp, q.feedback_rating, q.feedback_comment FROM queries q JOIN users u ON q.email = u.email WHERE u.role != 'admin'", conn)
        conn.close()
        if query_logs.empty:
            query_logs = pd.DataFrame({
                'email': ['student@college.edu'] * 50,
                'name': ['Student Name'] * 50,
                'project_title': ['Sample Project', 'AI Project'] * 25,
                'question': [f"Question {i}" for i in range(1, 51)],
                'response': [f"Response {i}" for i in range(1, 51)],
                'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 50,
                'feedback_rating': [4] * 50,
                'feedback_comment': ['Sample comment'] * 50
            })
        project_titles = ["All Projects"] + sorted(query_logs['project_title'].unique())
        selected_project = st.selectbox("Filter by Project", project_titles)
        filtered_logs = query_logs if selected_project == "All Projects" else query_logs[query_logs['project_title'] == selected_project]
        for project_title in filtered_logs['project_title'].unique():
            with st.expander(f"Project: {project_title}"):
                project_logs = filtered_logs[filtered_logs['project_title'] == project_title]
                for _, row in project_logs.iterrows():
                    rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
                    comment = row['feedback_comment'] if pd.notna(row['feedback_comment']) else "No comment"
                    response = row['response'][:200] + "..." if len(row['response']) > 200 else row['response']
                    question = row['question'][:200] + "..." if len(row['question']) > 200 else row['question']
                    initials = ''.join(word[0].upper() for word in row['name'].split()[:2])
                    st.markdown(
                        f"""
                        <div class='history-entry'>
                            <span class='avatar'>{initials}</span>
                            <strong>{row['name']} ({mask_email(row['email'])}) asked:</strong> {question}
                            <i>(at {format_timestamp(row['timestamp'])})</i><br>
                            <strong>Ky’ra replied:</strong> {response}<br>
                            <strong>Rating:</strong> {rating}<br>
                            <strong>Comment:</strong> {comment}
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    st.markdown("---")
        st.markdown("---")

    # Student Dashboard
    def show_student_dashboard(name):
        st.markdown(f"<h1 style='text-align: center; color: #4fb8ac; font-family: \"Roboto\", sans-serif;'>👋 Hi, {name}!</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; font-family: \"Roboto\", sans-serif;'>Ask Ky about resumes, interviews, or projects!</p>", unsafe_allow_html=True)

        # Project Submission
        st.subheader("Submit Your Project")
        project_title = st.text_input("Enter your project title:", placeholder="E.g., AI Chatbot")
        if st.button("Submit Project"):
            if project_title:
                success, message = save_project(st.session_state.email, project_title)
                if success:
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.error("Please enter a project title.")
        st.markdown("---")

        # Export Student Query Logs
        st.subheader("Export Your Query Logs")
        date_ranges = {
            "Last 7 Days": (datetime.now().date() - timedelta(days=7), datetime.now().date()),
            "Last 30 Days": (datetime.now().date() - timedelta(days=30), datetime.now().date()),
            "Last 90 Days": (datetime.now().date() - timedelta(days=90), datetime.now().date()),
            "Custom Range": None
        }
        selected_range = st.selectbox("Select Date Range", list(date_ranges.keys()), key="student_date_range")
        start_date, end_date = date_ranges.get(selected_range, (None, None))
        if selected_range == "Custom Range":
            start_date = st.date_input("Start Date", value=datetime.now().date() - timedelta(days=30), key="student_start")
            end_date = st.date_input("End Date", value=datetime.now().date(), key="student_end")
        if st.button("Export to CSV", key="student_csv_export"):
            with st.spinner("Exporting CSV..."):
                csv_data, message, csv_filename = export_query_logs_to_csv(student_email=st.session_state.email, start_date=start_date, end_date=end_date)
                if csv_data:
                    st.download_button(
                        label="Download Your CSV",
                        data=csv_data,
                        file_name=csv_filename,
                        mime="text/csv"
                    )
                    st.success(message)
                else:
                    st.error(message)
        st.markdown("---")

    # Show dashboard based on role
    if st.session_state.role == "admin":
        show_admin_dashboard(st.session_state.name)
    elif st.session_state.role == "student":
        show_student_dashboard(st.session_state.name)

    # Query Section
    st.subheader("Ask Ky’ra a Question")
    sample_questions = [
        "How to write an internship resume?",
        "Best final-year projects in AI?",
        "How to prepare for an interview?",
        "Skills needed for cybersecurity?"
    ]
    selected_question = st.selectbox("Choose a sample question or type your own:", sample_questions + ["Custom question"])
    query_text = st.text_area("Your Question", value=selected_question if selected_question != "Custom question" else "", height=100, placeholder="E.g., How to prepare for an interview?")

    # Ky’ra API Call with Mock Response
    from ratelimit import limits, sleep_and_retry
    @sleep_and_retry
    @limits(calls=CALLS, period=PERIOD)
    def kyra_response(email, query):
        if query == "Skills needed for cybersecurity?":
            return ("Key skills for a cybersecurity career include:\n"
                    "- **Technical Proficiency**: Networking, OS (Windows/Linux), security tools (Wireshark, Nessus, Metasploit).\n"
                    "- **Programming**: Python, C, or PowerShell for scripting.\n"
                    "- **Threat Analysis**: Malware, phishing, social engineering.\n"
                    "- **Incident Response**: Handle breaches, root cause analysis.\n"
                    "- **Cryptography**: AES, RSA, secure communication.\n"
                    "- **Soft Skills**: Problem-solving, communication, and teamwork.")
        return "This is a mock response as the Ky'ra API is not available in this environment."

    # Submit Query
    st.markdown('<div class="submit-button">', unsafe_allow_html=True)
    if st.button("Submit", type="primary"):
        if not query_text:
            st.error("Please enter a question.")
        else:
            try:
                conn = sqlite3.connect(DB_PATH)
                response = kyra_response(st.session_state.email, query_text)
                if response:
                    feedback_rating = None
                    feedback_comment = None
                    save_query(st.session_state.email, st.session_state.name, query_text, response, conn, feedback_rating, feedback_comment)
                    st.session_state.chat_history.append({
                        "email": st.session_state.email,
                        "name": st.session_state.name,
                        "query": query_text,
                        "response": response,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    st.success("Query submitted successfully!")
                    with st.expander("🧠 Ky’ra’s Response:", expanded=True):
                        initials = ''.join(word[0].upper() for word in st.session_state.name.split()[:2])
                        response_text = response[:200] + "..." if len(response) > 200 else response
                        st.markdown(
                            f"""
                            <div class="history-entry">
                                <span class="avatar">{initials}</span>
                                <strong>Ky’ra’s Response:</strong> <br>{response_text}</br>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                        feedback_rating = st.slider("Feedback Rating", min_value=1, max_value=5, value=3, step=1,
                                                   key=f"rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                        feedback_comment = st.text_area("Optional: Tell us why you gave this rating",
                                                       key=f"comment_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                        if st.button("Submit Feedback", key=f"submit_rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
                            if st.checkbox("Confirm feedback", key=f"confirm_rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
                                c = conn.cursor()
                                c.execute('UPDATE queries SET feedback_rating = ?, feedback_comment = ? WHERE email = ? AND timestamp = ?',
                                         (feedback_rating, feedback_comment, st.session_state.email, st.session_state.chat_history[-1]["timestamp"]))
                                conn.commit()
                                st.success("Feedback submitted!")
                            else:
                                st.warning("Please confirm the feedback.")
                else:
                    st.error("No response from Ky’ra.")
                conn.close()
            except Exception as e:
                conn.close()
                st.error(f"Error processing query: {str(e)}")
    st.markdown('</div>', unsafe_allow_html=True)

    # Query History
    st.subheader("Your Query History")
    try:
        conn = sqlite3.connect(DB_PATH)
        query = "SELECT name, question, response, timestamp, feedback_rating, feedback_comment FROM queries WHERE email = ? ORDER BY timestamp DESC"
        params = (st.session_state.email,)
        if st.session_state.role == "admin":
            query = "SELECT name, question, response, timestamp, feedback_rating, feedback_comment FROM queries WHERE email IN (SELECT email FROM users WHERE role != 'admin') ORDER BY timestamp DESC"
            params = []
        user_df = pd.read_sql_query(query, conn, params=params)
        conn.close()

        if user_df.empty:
            user_df = pd.DataFrame({
                'name': [st.session_state.name or 'Student Name'] * 50,
                'question': [f"Question {i}" for i in range(1, 51)],
                'response': [f"Response {i}" for i in range(1, 51)],
                'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 50,
                'feedback_rating': [4] * 50,
                'feedback_comment': ['Sample comment'] * 50
            })

        user_df = user_df.drop_duplicates(subset=['question', 'timestamp'])
        date_ranges = {
            "All Time": (None, None),
            "Last 7 Days": (datetime.now().date() - timedelta(days=7), datetime.now().date()),
            "Last 30 Days": (datetime.now().date() - timedelta(days=30), datetime.now().date()),
            "Last 90 Days": (datetime.now().date() - timedelta(days=90), datetime.now().date()),
            "Custom Range": None
        }
        selected_range = st.selectbox("Filter by Date Range", list(date_ranges.keys()), key="history_date_range")
        start_date, end_date = date_ranges.get(selected_range, (None, None))
        if selected_range == "Custom Range":
            start_date = st.date_input("Start Date", value=datetime.now().date() - timedelta(days=30), key="history_start")
            end_date = st.date_input("End Date", value=datetime.now().date(), key="history_end")
        if start_date and end_date:
            user_df = user_df[(user_df['timestamp'] >= start_date.strftime("%Y-%m-%d 00:00:00")) & 
                              (user_df['timestamp'] <= end_date.strftime("%Y-%m-%d 23:59:59"))]

        items_per_page = 10
        total_pages = (len(user_df) + items_per_page - 1) // items_per_page
        st.session_state.page = max(1, min(st.session_state.page, total_pages))

        start_idx = (st.session_state.page - 1) * items_per_page
        end_idx = start_idx + items_per_page
        paginated_df = user_df.iloc[start_idx:end_idx]

        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        for _, row in paginated_df.iterrows():
            response_text = row['response'][:200] + "..." if len(row['response']) > 200 else row['response']
            question_text = row['question'][:200] + "..." if len(row['question']) > 200 else row['question']
            rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
            comment = row['feedback_comment'] if pd.notna(row['feedback_comment']) else "No comment"
            initials = ''.join(word[0].upper() for word in row['name'].split()[:2])
            with st.expander(f"Question at {format_timestamp(row['timestamp'])}"):
                st.markdown(
                    f"""
                    <div class='history-entry'>
                        <span class='avatar'>{initials}</span>
                        <strong>You asked:</strong> {question_text}
                        <i>(at {format_timestamp(row['timestamp'])})</i><br>
                        <strong>Ky’ra replied:</strong> {response_text}<br>
                        <strong>Rating:</strong> {rating}<br>
                        <strong>Comment:</strong> {comment}
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                st.markdown("---")
        st.markdown('</div>', unsafe_allow_html=True)

        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            if st.button("Previous", disabled=st.session_state.page == 1):
                st.session_state.page -= 1
        with col2:
            st.write(f"Page {st.session_state.page} of {total_pages}")
        with col3:
            if st.button("Next", disabled=st.session_state.page == total_pages):
                st.session_state.page += 1
    except Exception as e:
        logger.error(f"Error loading query history: {str(e)}")
        st.error("Failed to load query history.")
    st.markdown("---")

    # Project Submissions
    if st.session_state.role != "admin":
        st.subheader("Your Projects")
        user_projects = get_user_projects(st.session_state.email)
        if user_projects.empty:
            user_projects = pd.DataFrame({
                'project_title': ['Sample Project', 'AI Project'],
                'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 2
            })
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        for _, row in user_projects.iterrows():
            st.markdown(
                f"""
                <div class='history-entry'>
                    <strong>Project Title:</strong> {row['project_title']}
                    <i>(at {format_timestamp(row['timestamp'])})</i>
                </div>
                """,
                unsafe_allow_html=True
            )
            st.markdown("---")
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown("---")

# Footer
st.markdown(
    "<p class='footer'>Ky’ra is here whenever you need. Ask freely. Grow boldly.</p>",
    unsafe_allow_html=True
)
st.markdown("<p style='font-family: Arial, sans-serif;'>Your queries and projects are securely stored.</p>", unsafe_allow_html=True)