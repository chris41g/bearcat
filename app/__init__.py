from flask import Flask
from config import Config
import os
import logging
from logging.handlers import RotatingFileHandler
from app.extensions import db, login_manager, socketio

def create_app(config_class=Config):
    # Initialize Flask app
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)
    
    # Configure logging
    if not os.path.exists(app.config['LOG_PATH']):
        os.makedirs(app.config['LOG_PATH'])
    
    file_handler = RotatingFileHandler(
        os.path.join(app.config['LOG_PATH'], 'network_discovery.log'),
        maxBytes=10240,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Network Discovery Web starting up')
    
    # Register blueprints
    from app.routes import dashboard_bp, scans_bp, queries_bp
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp, url_prefix='/scans')
    app.register_blueprint(queries_bp, url_prefix='/queries')
    
    # Register error handlers
    from app.errors import register_error_handlers
    register_error_handlers(app)
    
    # Setup login manager user loader
    from app.models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Register main routes
    from app.routes.main import main_bp
    app.register_blueprint(main_bp)
    
    # Add context processor for 'now' variable
    @app.context_processor
    def inject_now():
        from datetime import datetime
        return {'now': datetime.now()}

    @app.after_request
    def add_header(response):
        # Fix content type headers for HTML responses
        if response.mimetype == 'text/html':
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
    
        # Add cache control headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
    
        return response

    return app

# Import models to ensure they are registered with SQLAlchemy
from app import models
