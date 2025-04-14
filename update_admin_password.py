from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    # Get the admin user
    admin = User.query.filter_by(username='admin').first()
    
    if not admin:
        print("Admin user not found in database!")
    else:
        # Set new password
        new_password = 'Expl0r3r'  # Replace with your desired password
        admin.set_password(new_password)
        db.session.commit()
        print(f"Admin password updated successfully to: {new_password}")
