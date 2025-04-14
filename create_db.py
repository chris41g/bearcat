from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    # Create all database tables
    db.create_all()
    
    # Check if admin user exists, if not create it
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('changeme')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully!")
    
    print("Database initialized successfully!")
