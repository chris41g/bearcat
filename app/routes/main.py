from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from app.forms import LoginForm
from app.models import User
from app.extensions import db
from datetime import datetime
import os
import subprocess
main_bp = Blueprint('main', __name__)

@main_bp.route('/testsudo')
def testsudo():
    result = subprocess.run(
        ["sudo", "/opt/activediscovery/b-activedisc.py",'--help'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"


@main_bp.route('/')
def index():
    """Redirect to dashboard if logged in, otherwise to login page."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    return redirect(url_for('main.login'))

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        # Check if this is the first login (admin setup)
        if not user and form.username.data == current_app.config['ADMIN_USERNAME']:
            # Create admin user with default password
            user = User(
                username=current_app.config['ADMIN_USERNAME'],
                email='admin@example.com',
                is_admin=True
            )
            user.set_password(current_app.config['ADMIN_PASSWORD'])
            db.session.add(user)
            db.session.commit()
            flash('Admin account created with default password. Please change it immediately!', 'warning')
        
        # Check if credentials are valid
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            user.last_login = datetime.now()
            db.session.commit()
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard.index')
            return redirect(next_page)
        else:
            flash('Invalid username or password', 'danger')
    
    # Use our fixed template
    return render_template('login_fixed.html', title='Sign In', form=form)

@main_bp.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.login'))

@main_bp.route('/login_test')
def login_test():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Login</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body>
        <h1>Bearcat Login Test</h1>
        <p>This is a simple test page. If you can see this text, the basic rendering is working.</p>
    </body>
    </html>
    """

@main_bp.route('/about')
def about():
    """Show about page with application info."""
    # Get version info
    version = "1.0.0"  # Default version
    
    # Try to get version from git if available
    try:
        import subprocess
        git_version = subprocess.check_output(['git', 'describe', '--tags']).decode('utf-8').strip()
        if git_version:
            version = git_version
    except:
        pass
    
    # Get database info
    db_size = 0
    try:
        if os.path.exists(current_app.config['DATABASE_PATH']):
            db_size = os.path.getsize(current_app.config['DATABASE_PATH']) / (1024 * 1024)  # Size in MB
    except:
        pass
    
    return render_template('about.html', title='About', version=version, db_size=db_size)
