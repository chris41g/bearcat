from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    # Check if running in development mode
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    # Start SocketIO server with eventlet (allows for concurrency)
    from app.extensions import socketio
    socketio.run(app, host='0.0.0.0', port=5000, debug=debug_mode)
