# wsgi.py — PythonAnywhere WSGI entry point
# This file tells PythonAnywhere how to run the Flask app.

import sys
import os

# Add your project directory to the path
# PythonAnywhere will replace this path automatically when you set it up
project_home = '/home/ranjithbrs/CertValid'
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set environment variable for production
os.environ['FLASK_ENV'] = 'production'

from app import app as application  # noqa
