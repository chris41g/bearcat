import subprocess
import threading
import os
import re
import time
import tempfile  # Added missing import
from datetime import datetime
from flask import current_app
import sqlite3
from app.extensions import socketio, db
from app.models import ScanJob
import sys

def update_job_status(app, job_id, status, progress=None, hosts_scanned=None, hosts_online=None, 
                      session_id=None, log_output=None, completed=False, total_hosts=None):
    """Update the status of a scan job in the database."""
    with app.app_context():
        # Use the standard session
        session = db.session()
        job = session.query(ScanJob).get(job_id)
        
        if job:
            job.status = status
            
            if progress is not None:
                job.progress = progress
            
            if hosts_scanned is not None:
                job.hosts_scanned = hosts_scanned
            
            if hosts_online is not None:
                job.hosts_online = hosts_online
            
            if total_hosts is not None:
                job.total_hosts = total_hosts
            
            if session_id is not None:
                job.session_id = session_id
            
            if log_output is not None:
                # Append to existing log
                if job.log_output:
                    job.log_output += "\n" + log_output
                else:
                    job.log_output = log_output
            
            # Mark completion time if completed
            if completed:
                job.completed_at = datetime.now()
            
            try:
                session.commit()
                print(f"DB updated successfully. Job {job_id} status: {status}, progress: {progress if progress is not None else 'N/A'}%")
                
                # Get progress data
                progress_data = job.get_progress_data()
                
                # Emit socket event for real-time updates
                socketio.emit('scan_update', progress_data)
                print(f"SocketIO event 'scan_update' emitted with data: {progress_data}")
            except Exception as e:
                print(f"Error updating job status: {str(e)}")
                session.rollback()
            
            session.close()

def find_latest_session_id(app):
    """Find the latest scan session ID in the database."""
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(id) FROM scan_sessions")
        result = cursor.fetchone()
        conn.close()
        return result[0] if result and result[0] else None
    except Exception as e:
        print(f"Error getting session ID: {str(e)}")
        return None

def is_scan_already_running(target):
    """Check if a scan with the same target is already running."""
    try:
        # Look for existing processes with the same target
        cmd = f"ps -aux | grep b-activedisc | grep '{target}' | grep -v grep"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # If we found matching processes
        if result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            if len(lines) > 0:  # More than one process found
                print(f"Found existing processes running for target {target}:")
                for line in lines:
                    print(f"  {line}")
                return True
        
        return False
    except Exception as e:
        print(f"Error checking for running scans: {str(e)}")
        return False

def run_scanner(app, job_id, password_file=None):
    """Run the network scanner script as a subprocess and monitor progress."""
    import sys
    print("********* USING UPDATED SCANNER.PY WITH DUPLICATE PROCESS PREVENTION *********")
    print(f"Starting scanner for job {job_id}")
    
    # Get password if provided in a file
    password = None
    if password_file and os.path.exists(password_file):
        try:
            with open(password_file, 'r') as f:
                password = f.read().strip()
            # Delete the file after reading
            os.unlink(password_file)
            print(f"Read password from file (length: {len(password)})")
        except Exception as e:
            print(f"Error reading password file: {str(e)}")
    
    # Get initial job data within app context
    with app.app_context():
        session = db.session()
        job = session.query(ScanJob).get(job_id)
        if not job:
            print(f"Job {job_id} not found")
            session.close()
            return
        
        # Extract needed attributes while in session
        job_target_type = job.target_type
        job_target = job.target
        job_scan_type = job.scan_type
        job_workers = job.workers
        job_username = job.username
        job_find_foxit = job.find_foxit
        
        # Add more debug output
        print(f"Job details from DB: target_type={job_target_type}, target={job_target}, scan_type={job_scan_type}")
        
        # Mark the job as started
        job.status = 'running'
        job.started_at = datetime.now()
        job.progress = 0
        job.total_hosts = 1 if job_target_type == 'target' else 0
        
        try:
            session.commit()
            print(f"Job {job_id} marked as running")
        except Exception as e:
            print(f"Error marking job as started: {str(e)}")
            session.rollback()
            session.close()
            return
        
        session.close()
    
    # Check if a scan with the same target is already running
    if is_scan_already_running(job_target):
        print(f"WARNING: A scan with target {job_target} is already running!")
        update_job_status(app, job_id, 'failed', 
                        log_output=f"A scan with the same target is already running. Please wait for it to complete.",
                        completed=True)
        return
    
    # Build the command based on previously extracted parameters
    scanner_path = app.config['SCANNER_SCRIPT_PATH']
    python_path = app.config['PYTHON_PATH']
    db_path = app.config['DATABASE_PATH']
    
    # Check if script exists and is executable
    if not os.path.exists(scanner_path):
        print(f"ERROR: Scanner script not found at {scanner_path}")
        update_job_status(app, job_id, 'failed', 
                         log_output=f"Scanner script not found at {scanner_path}", 
                         completed=True)
        return
    
    # Make script executable if it isn't already
    if not os.access(scanner_path, os.X_OK):
        try:
            os.chmod(scanner_path, 0o755)
            print(f"Made script executable: {scanner_path}")
        except Exception as e:
            print(f"WARNING: Could not make script executable: {e}")
    
    # Create a temporary script to execute the command
    # This approach avoids issues with escaping special characters
    fd, script_path = tempfile.mkstemp(prefix="scan_script_", suffix=".sh")
    try:
        with os.fdopen(fd, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# Temporary script to execute scan\n\n")
            
            # Build the command
            cmd = f"{python_path} {scanner_path}"
            
            # Add target parameters
            if job_target_type == 'subnet':
                cmd += f" -s {job_target}"
            elif job_target_type == 'range':
                cmd += f" -r {job_target}"
            elif job_target_type == 'target':
                cmd += f" -t {job_target}"
            elif job_target_type == 'local':
                cmd += " -l"
            
            # Add scan type
            if job_scan_type == 'full' or job_scan_type.lower() == 'full' or 'full' in job_scan_type:
                cmd += " -f"
            
            # Add workers
            cmd += f" -w {job_workers}"
            
            # Add database path
            cmd += f" --db-path {db_path}"
            
            # Add Windows authentication if provided
            if job_username:
                cmd += f" -u '{job_username}'"
                
                if password:
                    cmd += f" -p '{password}'"
                else:
                    cmd += " --ask-password"
            
            # Add Foxit license search if enabled
            if job_find_foxit:
                cmd += " --find-foxit-license"
            
            # Write the full command to the script
            f.write(f"sudo {cmd}\n")
        
        # Make the script executable
        os.chmod(script_path, 0o700)
        
        # Create a safe version for logging (without the actual password)
        safe_cmd = f"sudo {python_path} {scanner_path}"
        if job_target_type == 'subnet':
            safe_cmd += f" -s {job_target}"
        elif job_target_type == 'range':
            safe_cmd += f" -r {job_target}"
        elif job_target_type == 'target':
            safe_cmd += f" -t {job_target}"
        elif job_target_type == 'local':
            safe_cmd += " -l"
        
        if job_scan_type == 'full' or job_scan_type.lower() == 'full' or 'full' in job_scan_type:
            safe_cmd += " -f"
        
        safe_cmd += f" -w {job_workers} --db-path {db_path}"
        
        if job_username:
            safe_cmd += f" -u '{job_username}'"
            if password:
                safe_cmd += " -p '[PASSWORD REDACTED]'"
            else:
                safe_cmd += " --ask-password"
        
        if job_find_foxit:
            safe_cmd += " --find-foxit-license"
        
        # Print environment info for debugging
        print("=== Environment Information ===")
        print(f"Python executable: {sys.executable}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"PATH environment variable: {os.environ.get('PATH', '')}")
        print(f"Command being run (via script): {safe_cmd}")
        print(f"Script path: {script_path}")
        print("==============================")
        
        # Log the command (but mask password)
        print(f"Running command via script: {safe_cmd}")
        update_job_status(app, job_id, 'running', 
                         log_output=f"Starting scan with command: {safe_cmd}",
                         progress=10)  # Show some initial progress
        
        try:
            # Create process with pipes for stdout/stderr
            process = subprocess.Popen(
                [script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            print(f"Process started with PID: {process.pid}")
            
            # Initialize counters
            hosts_scanned = 0
            hosts_online = 0
            total_hosts = 1 if job_target_type == 'target' else 0
            progress = 10
            
            # Regular expressions to extract progress information
            progress_regex = re.compile(r'Progress: (\d+)/(\d+) \((\d+\.\d+)%\) \| Online: (\d+)')
            completion_regex = re.compile(r'Scan completed in (\d+\.\d+) seconds')
            online_host_regex = re.compile(r'(\d+\.\d+\.\d+\.\d+) - (Online|Offline)')
            sudo_regex = re.compile(r'(\[sudo\]|sudo:).*(password|password for)')
            
            print(f"Process started, monitoring output...")
            
            # For single target scans, update progress immediately to show activity
            if job_target_type == 'target':
                update_job_status(
                    app, 
                    job_id, 
                    'running', 
                    progress=25.0,
                    hosts_scanned=0,
                    hosts_online=0,
                    total_hosts=1
                )
            
            # Track start time for timeout handling
            start_time = time.time()
            last_update_time = start_time
            
            # Monitor stdout and stderr for progress updates and sudo prompts
            while True:
                # Check if process has terminated
                if process.poll() is not None:
                    print(f"Process terminated with exit code: {process.poll()}")
                    break
                
                # Check stderr for sudo password prompts without blocking
                if process.stderr.readable():
                    stderr_line = process.stderr.readline()
                    if stderr_line:
                        stderr_line = stderr_line.strip()
                        print(f"STDERR: {stderr_line}")
                        
                        # Check for sudo password prompt
                        if sudo_regex.search(stderr_line):
                            print("Detected sudo password prompt in stderr, script requires sudo")
                            update_job_status(app, job_id, 'failed', 
                                             log_output="Error: Script requires sudo privileges. Please configure sudo to allow running this script without a password using 'NOPASSWD' in the sudoers file.",
                                             completed=True)
                            # Terminate the process
                            process.terminate()
                            break
                        
                        # Log other stderr output
                        update_job_status(app, job_id, 'running', log_output=f"ERROR: {stderr_line}")
                
                # Read stdout line by line
                if process.stdout.readable():
                    line = process.stdout.readline()
                    if not line:
                        # No more output, but process may still be running
                        time.sleep(0.1)
                        continue
                        
                    line = line.strip()
                    print(f"Process output: {line}")
                    
                    # Check for sudo password prompt in stdout
                    if sudo_regex.search(line):
                        print("Detected sudo password prompt in stdout, script requires sudo")
                        update_job_status(app, job_id, 'failed', 
                                         log_output="Error: Script requires sudo privileges. Please configure sudo to allow running this script without a password using 'NOPASSWD' in the sudoers file.",
                                         completed=True)
                        # Terminate the process
                        process.terminate()
                        break
                    
                    update_job_status(app, job_id, 'running', log_output=line)
                    
                    # Check for progress update
                    progress_match = progress_regex.search(line)
                    if progress_match:
                        hosts_scanned = int(progress_match.group(1))
                        total_hosts = int(progress_match.group(2))
                        progress = float(progress_match.group(3))
                        hosts_online = int(progress_match.group(4))
                        
                        print(f"Progress detected: {hosts_scanned}/{total_hosts} ({progress}%), {hosts_online} online")
                        
                        # Update job status
                        update_job_status(
                            app, 
                            job_id, 
                            'running', 
                            progress=progress,
                            hosts_scanned=hosts_scanned,
                            hosts_online=hosts_online,
                            total_hosts=total_hosts
                        )
                    
                    # Check for host status messages
                    online_match = online_host_regex.search(line)
                    if online_match:
                        host_ip = online_match.group(1)
                        status = online_match.group(2)
                        
                        # For single target scans, update based on host status
                        if job_target_type == 'target' and host_ip == job_target:
                            hosts_scanned = 1
                            hosts_online = 1 if status == 'Online' else 0
                            
                            update_job_status(
                                app,
                                job_id,
                                'running',
                                progress=75.0,  # Host found
                                hosts_scanned=hosts_scanned,
                                hosts_online=hosts_online,
                                total_hosts=1
                            )
                    
                    # Check for completion
                    if completion_regex.search(line):
                        print("Completion detected")
                        
                        # Find session ID
                        session_id = find_latest_session_id(app)
                        
                        update_job_status(
                            app,
                            job_id,
                            'completed',
                            progress=100.0,
                            hosts_scanned=hosts_scanned or 1,
                            hosts_online=hosts_online,
                            session_id=session_id,
                            completed=True
                        )
                        break
                
                # Check for timeout
                current_time = time.time()
                
                # Timeout for all scans - 120 seconds
                if current_time - start_time > 120:
                    print(f"Scan timeout (120s), marking as completed")
                    update_job_status(
                        app,
                        job_id,
                        'completed',
                        progress=100.0,
                        hosts_scanned=hosts_scanned or 1,
                        hosts_online=hosts_online,
                        completed=True
                    )
                    
                    # Try to terminate gracefully
                    try:
                        process.terminate()
                    except:
                        pass
                    break
                
                # Send periodic updates every 3 seconds
                if current_time - last_update_time > 3:
                    # Calculate new progress for time-based progress
                    elapsed_pct = min(90, ((current_time - start_time) / 120) * 100)
                    
                    # Use the higher of actual progress or time-based progress
                    effective_progress = max(progress, elapsed_pct)
                    
                    update_job_status(
                        app,
                        job_id,
                        'running',
                        progress=effective_progress,
                        hosts_scanned=hosts_scanned,
                        hosts_online=hosts_online,
                        total_hosts=total_hosts or 1
                    )
                    
                    last_update_time = current_time
                    print(f"Sent progress update: {effective_progress}%")
            
            # Process any remaining output
            remaining_output = process.stdout.read()
            if remaining_output:
                print(f"Remaining output: {remaining_output}")
                update_job_status(app, job_id, 'running', log_output=remaining_output)
            
            # Check for any stderr output
            stderr_output = process.stderr.read()
            if stderr_output:
                print(f"Process stderr: {stderr_output}")
                
                # Check for sudo prompt in remaining stderr
                if sudo_regex.search(stderr_output):
                    update_job_status(app, job_id, 'failed', 
                                   log_output="Error: Script requires sudo privileges. Please configure sudo to allow running this script without a password using 'NOPASSWD' in the sudoers file.",
                                   completed=True)
                else:
                    update_job_status(app, job_id, 'running', log_output=f"ERRORS: {stderr_output}")
            
            # Get final return code
            return_code = process.poll()
            print(f"Final return code: {return_code}")
            
            # Mark job as completed or failed based on return code
            with app.app_context():
                session = db.session()
                job = session.query(ScanJob).get(job_id)
                
                if job and job.status != 'completed':
                    if return_code != 0:
                        job.status = 'failed'
                        job.log_output = (job.log_output or '') + f"\nScan failed with return code {return_code}"
                    else:
                        job.status = 'completed'
                    
                    job.completed_at = datetime.now()
                    session.commit()
                    
                    # Get fresh data for socketio
                    data = job.get_progress_data()
                    socketio.emit('scan_update', data)
                
                session.close()
            
        except Exception as e:
            print(f"Exception running scanner: {str(e)}")
            update_job_status(app, job_id, 'failed', log_output=f"Exception: {str(e)}", completed=True)
    
    finally:
        # Clean up the temporary script
        try:
            os.remove(script_path)
            print(f"Removed temporary script: {script_path}")
        except Exception as e:
            print(f"Error removing temporary script: {str(e)}")

def start_scan_job(job_id, password_file=None):
    """Start a scan job in a separate thread."""
    from flask import current_app
    print(f"start_scan_job called for job_id: {job_id}, password_file: {password_file}")
    
    try:
        app = current_app._get_current_object()  # Get the actual app object
        print(f"Got current_app object")
        
        # Use threading.Thread directly
        thread = threading.Thread(target=run_scanner, args=(app, job_id, password_file))
        thread.daemon = True
        print(f"Created thread for job_id: {job_id}")
        
        # Start the thread
        thread.start()
        print(f"Started thread for job_id: {job_id}")
        
        return thread
    except Exception as e:
        print(f"Error starting scan job thread: {str(e)}")
        # Try to update the job status to failed
        try:
            with current_app.app_context():
                job = ScanJob.query.get(job_id)
                if job:
                    job.status = 'failed'
                    job.log_output = f"Failed to start scan thread: {str(e)}"
                    job.completed_at = datetime.now()
                    db.session.commit()
        except Exception as inner_e:
            print(f"Error updating job status: {str(inner_e)}")
        return None

def get_running_jobs():
    """Get a list of currently running scan jobs."""
    return ScanJob.query.filter_by(status='running').all()

def cancel_scan_job(job_id):
    """Attempt to cancel a running scan job."""
    # This implementation is a placeholder.
    # In a real implementation, you'd need to track the subprocess PID
    # and use process.terminate() or os.kill() to stop it.
    
    job = ScanJob.query.get(job_id)
    if job and job.status == 'running':
        job.status = 'cancelled'
        job.completed_at = datetime.now()
        db.session.commit()
        
        # Emit socket event for real-time updates
        socketio.emit('scan_update', job.get_progress_data())
        return True
    return False
