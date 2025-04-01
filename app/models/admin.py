"""
Admin model and authentication logic
"""

import hashlib
import secrets
import os
import json
from functools import wraps
from flask import session, redirect, url_for, flash, request

class AdminModel:
    """Model for admin users and authentication"""
    
    def __init__(self, admin_file):
        self.admin_file = admin_file
        
    def hash_password(self, password):
        """Hash a password for storing"""
        salt = secrets.token_hex(16)
        hash_obj = hashlib.sha256(salt.encode() + password.encode())
        return salt + ':' + hash_obj.hexdigest()
    
    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt, stored_hash = stored_password.split(':')
        hash_obj = hashlib.sha256(salt.encode() + provided_password.encode())
        return hash_obj.hexdigest() == stored_hash
    
    def load_admins(self):
        """Load admin accounts from file"""
        if os.path.exists(self.admin_file):
            with open(self.admin_file, 'r') as f:
                return json.load(f)
        # Initialize with default admin if file doesn't exist
        default_admin = {
            "username": "admin", 
            "password": self.hash_password("password123")
        }
        admins = [default_admin]
        self.save_admins(admins)
        return admins
    
    def save_admins(self, admins):
        """Save admin accounts to file"""
        with open(self.admin_file, 'w') as f:
            json.dump(admins, f, indent=2)
    
    def is_admin(self, username, password):
        """Check if credentials match an admin account"""
        admins = self.load_admins()
        for admin in admins:
            if admin['username'] == username and self.verify_password(admin['password'], password):
                return True
        return False


def admin_required(f):
    """Authentication decorator for routes that require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Admin login required')
            return redirect(url_for('auth.admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function