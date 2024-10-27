import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Initialize the Flask application
app = Flask(__name__)
app = Flask(__name__, static_folder='../static')

app = Flask(__name__, template_folder='../templates')  # Points to the correct folder


# Configure the path to the SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))  # Get the directory where this file resides
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, '../sqlite/tasks.db')  # Define the database path
app.config['SECRET_KEY'] = 'your_secret_key'  # Use a secure and random string for the secret key

# Initialize the database object
db = SQLAlchemy(app)

# To avoid circular imports, import routes and models at the end
from app import routes  # Import routes after app and db are initialized
from app import models  # Import models after db is initialized to ensure the tables are created
