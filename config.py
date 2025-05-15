import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    FLASK_APP = os.environ.get('FLASK_APP') or 'run.py'
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'production'
    DEBUG = os.environ.get('DEBUG') == 'True'
    
    # Database settings
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or '/opt/sidney/network_discovery.db'
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATABASE_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Network Discovery settings
    DEFAULT_WORKERS = int(os.environ.get('DEFAULT_WORKERS') or 50)
    DEFAULT_SCAN_TYPE = os.environ.get('DEFAULT_SCAN_TYPE') or 'basic'
    SCANNER_SCRIPT_PATH = os.environ.get('SCANNER_SCRIPT_PATH') or '/opt/sidney/sidney-sudo-wrapper.sh'
    PYTHON_PATH = os.environ.get('PYTHON_PATH') or 'bash'
    
    # Authentication
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME') or 'admin'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    
    # Logging
    LOG_PATH = os.environ.get('LOG_PATH') or '/opt/sidney/logs'
    
    # Web interface settings
    ITEMS_PER_PAGE = int(os.environ.get('ITEMS_PER_PAGE') or 25)
