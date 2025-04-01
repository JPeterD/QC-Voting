"""
Authentication routes for the application
"""

from flask import Blueprint, render_template, session, current_app, request, redirect, url_for, flash
from app.models.admin import AdminModel

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    admin_model = AdminModel(current_app.config['ADMIN_FILE'])
    
    if session.get('admin_logged_in'):
        return redirect(url_for('main.home'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if admin_model.is_admin(username, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            
            # Redirect to the next page if specified, otherwise home
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('main.home'))
        else:
            flash('Invalid username or password')
    
    return render_template('admin_login.html')

@auth_bp.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('You have been logged out')
    return redirect(url_for('main.home'))