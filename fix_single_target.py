# Add this at the top of scanner.py
import time

# Update the run_scanner function to handle single IP targets better
def run_scanner(app, job_id):
    """Run the network scanner script as a subprocess and monitor progress."""
    print(f"Starting scanner for job {job_id}")
    with app.app_context():
        job = ScanJob.query.get(job_id)
        if not job:
            print(f"Job {job_id} not found")
            return
        
        # Mark the job as started
        job.status = 'running'
        job.started_at = datetime.now()
        try:
            db.session.commit()
            print(f"Job {job_id} marked as running")
        except Exception as e:
            print(f"Error marking job as started: {str(e)}")
            db.session.rollback()
            return
    
    # Build the command based on job parameters
    cmd = [app.config['PYTHON_PATH'], app.config['SCANNER_SCRIPT_PATH']]
    
    # Add target parameters
    if job.target_type == 'subnet':
        cmd.extend(['-s', job.target])
    elif job.target_type == 'range':
        cmd.extend(['-r', job.target])
    elif job.target_type == 'target':
        cmd.extend(['-t', job.target])
        # For single IP targets, set total_hosts=1 since we know we're scanning exactly one host
        with app.app_context():
            job.total_hosts = 1
            job.progress = 0
            db.session.commit()
    elif job.target_type == 'local':
        cmd.append('-l')
    
    # Add scan type
    if job.scan_type == 'full':
        cmd.append('-f')
    
    # Add workers
    cmd.extend(['-w', str(job.workers)])
    
    # Add database path
    cmd.extend(['--db-path', app.config['DATABASE_PATH']])
    
    # Add Windows authentication if provided
    if job.username:
        cmd.extend(['-u', job.username])
        cmd.append('--ask-password')
    
    # Add Foxit license search if enabled
    if job.find_foxit:
        cmd.append('--find-foxit-license')
    
    # Log the command (but mask password)
    safe_cmd = cmd.copy()
    if '--ask-password' in safe_cmd:
        safe_cmd.append('[PASSWORD REDACTED]')
    
    print(f"Running command: {' '.join(safe_cmd)}")
    update_job_status(app, job_id, 'running', log_output=f"Starting scan with command: {' '.join(safe_cmd)}")
    
    try:
        # Create process with pipes for stdin/stdout/stderr
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )
        
        # Skip password handling for now
        
        # Initialize counters
        hosts_scanned = 0
        hosts_online = 0
        total_hosts = job.total_hosts or 0
        
        # For single targets, set hosts_scanned=1 after a certain time if no output
        if job.target_type == 'target':
            # Wait a moment for the process to start scanning
            time.sleep(2)
            # If no output yet, consider the single host as "scanned" and update progress
            if hosts_scanned == 0:
                hosts_scanned = 1
                with app.app_context():
                    job.hosts_scanned = 1
                    job.progress = 50.0  # Show 50% progress
                    db.session.commit()
                update_job_status(
                    app, 
                    job_id, 
                    'running', 
                    progress=50.0,
                    hosts_scanned=1,
                    hosts_online=hosts_online,
                    total_hosts=1
                )
                print(f"Single target scan in progress, set progress to 50%")
        
        # Regular expressions to extract progress information
        progress_regex = re.compile(r'Progress: (\d+)/(\d+) \((\d+\.\d+)%\) \| Online: (\d+)')
        completion_regex = re.compile(r'Scan completed in (\d+\.\d+) seconds')
        online_host_regex = re.compile(r'(\d+\.\d+\.\d+\.\d+) - (Online|Offline)')
        
        print(f"Process started, monitoring output...")
        
        # Update status every 5 seconds even without new output,
        # to ensure progress is reflected in the UI
        last_time = time.time()
        start_time = last_time
        
        # Monitor stdout for progress updates
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                print("Process ended, no more output")
                break
            
            if line:
                line = line.strip()
                print(f"Process output: {line}")
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
                    
                    # For single target scans, this means we've scanned the host
                    if job.target_type == 'target' and host_ip == job.target:
                        hosts_scanned = 1
                        if status == 'Online':
                            hosts_online = 1
                        
                        update_job_status(
                            app,
                            job_id,
                            'running',
                            progress=100.0,  # Scanning single host is complete
                            hosts_scanned=1,
                            hosts_online=hosts_online,
                            total_hosts=1
                        )
                
                # Check for completion
                if completion_regex.search(line):
                    print("Completion detected")
                    # Need to find session ID for the scan
                    session_id = None
                    
                    # Scan database to find the latest session ID
                    try:
                        conn = sqlite3.connect(app.config['DATABASE_PATH'])
                        cursor = conn.cursor()
                        cursor.execute("SELECT MAX(id) FROM scan_sessions")
                        result = cursor.fetchone()
                        if result and result[0]:
                            session_id = result[0]
                            print(f"Found session ID: {session_id}")
                        conn.close()
                    except Exception as e:
                        print(f"Error getting session ID: {str(e)}")
                        update_job_status(app, job_id, 'completed', log_output=f"Error getting session ID: {str(e)}")
                    
                    # For single target, ensure hosts_scanned is set to 1
                    if job.target_type == 'target':
                        hosts_scanned = 1
                    
                    update_job_status(
                        app,
                        job_id,
                        'completed',
                        progress=100.0,
                        hosts_scanned=hosts_scanned,
                        hosts_online=hosts_online,
                        session_id=session_id,
                        completed=True
                    )
            
            # Timeout for single target scans
            current_time = time.time()
            if job.target_type == 'target' and current_time - start_time > 60:
                print("Single target scan timeout (60s), marking as completed")
                update_job_status(
                    app,
                    job_id,
                    'completed',
                    progress=100.0,
                    hosts_scanned=1,
                    hosts_online=hosts_online,
                    completed=True
                )
                process.terminate()
                break
            
            # If no new output for 5 seconds but job is still running,
            # update timestamp to keep websocket connection alive
            if current_time - last_time > 5 and process.poll() is None:
                print("No output for 5 seconds, sending keep-alive update")
                update_job_status(
                    app,
                    job_id,
                    'running',
                    progress=progress if 'progress' in locals() else 0,
                    hosts_scanned=hosts_scanned,
                    hosts_online=hosts_online
                )
                last_time = current_time
        
        # Check for any stderr output
        stderr_output = process.stderr.read()
        if stderr_output:
            print(f"Process stderr: {stderr_output}")
            update_job_status(app, job_id, 'running', log_output=f"ERRORS: {stderr_output}")
        
        # Check final return code
        return_code = process.poll()
        print(f"Process finished with return code: {return_code}")
        if return_code != 0:
            update_job_status(app, job_id, 'failed', log_output=f"Scan failed with return code {return_code}", completed=True)
        else:
            # Make sure the job is marked as completed if not already
            with app.app_context():
                job = ScanJob.query.get(job_id)
                if job.status != 'completed':
                    update_job_status(app, job_id, 'completed', completed=True)
        
    except Exception as e:
        print(f"Exception running scanner: {str(e)}")
        update_job_status(app, job_id, 'failed', log_output=f"Exception: {str(e)}", completed=True)
