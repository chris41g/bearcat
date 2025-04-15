from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from app.forms import ScanForm
from app.models import ScanJob
from app.extensions import db, socketio
from app.scanning.scanner import start_scan_job, cancel_scan_job
from datetime import datetime
import sqlite3
import os

scans_bp = Blueprint('scans', __name__)

@scans_bp.route('/')
@login_required
def index():
    """Show list of scan jobs."""
    page = request.args.get('page', 1, type=int)
    per_page = current_app.config['ITEMS_PER_PAGE']
    
    jobs = ScanJob.query.order_by(ScanJob.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    
    return render_template('scans/index.html', title='Scan Jobs', jobs=jobs)

@scans_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    """Create a new scan job."""
    form = ScanForm()
    
    if form.validate_on_submit():
        try:
            print(f"Form validated, creating new scan job")
            print(f"Form data: target_type={form.target_type.data}, target={form.target.data}, scan_type={form.scan_type.data}")
            
            # Get the plain text password from the form
            password_text = form.password.data
            print(f"DEBUG: Form password provided: {'Yes' if password_text else 'No'}")
            if password_text:
                print(f"DEBUG: Password length from form: {len(password_text)}")
            
            # Create new scan job
            job = ScanJob(
                name=form.name.data,
                target_type=form.target_type.data,
                target=form.target.data,
                scan_type=form.scan_type.data,
                workers=form.workers.data,
                username=form.username.data,
                find_foxit=form.find_foxit.data,
                status='pending',
                created_by=current_user.id
            )
            
            # Set password hash if provided
            if form.password.data:
                job.set_password(form.password.data)
            
            print(f"Adding job to database with scan_type={job.scan_type}")
            db.session.add(job)
            db.session.commit()
            print(f"Job created with ID: {job.id}, scan_type={job.scan_type}")
            
            # Create a temporary file to pass the password securely
            password_file = None
            if password_text:
                import tempfile
                fd, password_file = tempfile.mkstemp(prefix="scan_pwd_")
                with os.fdopen(fd, 'w') as f:
                    f.write(password_text)
                os.chmod(password_file, 0o600)  # Secure permissions
                print(f"Password stored in temporary file: {password_file}")
                print(f"DEBUG: Temporary file exists: {os.path.exists(password_file)}")
                print(f"DEBUG: Temporary file readable: {os.access(password_file, os.R_OK)}")
                print(f"DEBUG: Temporary file size: {os.path.getsize(password_file)}")
            
            # Start the scan job
            print(f"Starting scan job {job.id} with password_file: {password_file}")
            thread = start_scan_job(job.id, password_file)
            print(f"Scan job thread started: {thread}")
            
            flash(f'Scan job "{job.name}" started successfully!', 'success')
            return redirect(url_for('scans.view', job_id=job.id))
        except Exception as e:
            print(f"Error creating scan job: {str(e)}")
            flash(f'Error starting scan job: {str(e)}', 'danger')
            return render_template('scans/new.html', title='New Scan', form=form)
    
    return render_template('scans/new.html', title='New Scan', form=form)

@scans_bp.route('/<int:job_id>')
@login_required
def view(job_id):
    """View scan job details."""
    job = ScanJob.query.get_or_404(job_id)
    
    # Get session details if job is completed and has session ID
    session_info = None
    if job.status == 'completed' and job.session_id:
        session_info = get_session_info(job.session_id)
    
    return render_template(
        'scans/view.html', 
        title=f'Scan: {job.name}',
        job=job,
        session_info=session_info
    )

@scans_bp.route('/<int:job_id>/cancel', methods=['POST'])
@login_required
def cancel(job_id):
    """Cancel a running scan job."""
    job = ScanJob.query.get_or_404(job_id)
    
    if job.status != 'running':
        flash('Only running jobs can be cancelled.', 'warning')
    else:
        if cancel_scan_job(job_id):
            flash('Scan job cancelled successfully.', 'success')
        else:
            flash('Failed to cancel scan job.', 'danger')
    
    return redirect(url_for('scans.view', job_id=job_id))

@scans_bp.route('/<int:job_id>/delete', methods=['POST'])
@login_required
def delete(job_id):
    """Delete a scan job."""
    job = ScanJob.query.get_or_404(job_id)
    
    if job.status == 'running':
        flash('Cannot delete a running job. Cancel it first.', 'warning')
        return redirect(url_for('scans.view', job_id=job_id))
    
    job_name = job.name
    db.session.delete(job)
    db.session.commit()
    
    flash(f'Scan job "{job_name}" deleted.', 'success')
    return redirect(url_for('scans.index'))

@scans_bp.route('/<int:job_id>/progress')
@login_required
def progress(job_id):
    """Get scan job progress data."""
    job = ScanJob.query.get_or_404(job_id)
    return jsonify(job.get_progress_data())

def get_session_info(session_id):
    """Get information about a scan session from the database."""
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get session info
        cursor.execute("""
            SELECT * FROM scan_sessions WHERE id = ?
        """, (session_id,))
        
        session = cursor.fetchone()
        if not session:
            return None
        
        # Get count of online hosts for this session
        cursor.execute("""
            SELECT COUNT(*) as count FROM hosts 
            WHERE status = 'online' AND 
                  scan_time BETWEEN ? AND ?
        """, (session['start_time'], session['end_time'] or datetime.now().isoformat()))
        
        online_hosts = cursor.fetchone()['count']
        
        # Get OS distribution
        cursor.execute("""
            SELECT os, COUNT(*) as count FROM hosts 
            WHERE status = 'online' AND 
                  scan_time BETWEEN ? AND ?
                  AND os != ''
            GROUP BY os
            ORDER BY count DESC
            LIMIT 5
        """, (session['start_time'], session['end_time'] or datetime.now().isoformat()))
        
        os_distribution = cursor.fetchall()
        
        # Get top ports
        cursor.execute("""
            SELECT s.port, s.service_name, COUNT(*) as count
            FROM services s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.status = 'online' AND 
                  h.scan_time BETWEEN ? AND ?
            GROUP BY s.port, s.service_name
            ORDER BY count DESC
            LIMIT 10
        """, (session['start_time'], session['end_time'] or datetime.now().isoformat()))
        
        top_ports = cursor.fetchall()
        
        conn.close()
        
        return {
            'session': dict(session),
            'online_hosts': online_hosts,
            'os_distribution': [dict(row) for row in os_distribution],
            'top_ports': [dict(row) for row in top_ports]
        }
        
    except Exception as e:
        current_app.logger.error(f"Error getting session info: {str(e)}")
        return None

@scans_bp.route('/<int:job_id>/results')
@login_required
def results(job_id):
    """View scan results."""
    job = ScanJob.query.get_or_404(job_id)
    
    if job.status != 'completed' or not job.session_id:
        flash('No results available for this scan job.', 'warning')
        return redirect(url_for('scans.view', job_id=job_id))
    
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get session info
        cursor.execute("""
            SELECT * FROM scan_sessions WHERE id = ?
        """, (job.session_id,))
        
        session = cursor.fetchone()
        if not session:
            flash('Scan session not found in database.', 'warning')
            return redirect(url_for('scans.view', job_id=job_id))
        
        # Get basic results (paginate to handle large scans)
        page = request.args.get('page', 1, type=int)
        per_page = current_app.config['ITEMS_PER_PAGE']
        offset = (page - 1) * per_page
        
        # Get total count of hosts
        cursor.execute("""
            SELECT COUNT(*) as count FROM hosts 
            WHERE scan_time BETWEEN ? AND ?
              AND status = 'online'
        """, (session['start_time'], session['end_time'] or datetime.now().isoformat()))
        total = cursor.fetchone()['count']
        
        # Get paginated hosts
        cursor.execute("""
            SELECT * FROM hosts 
            WHERE scan_time BETWEEN ? AND ?
              AND status = 'online'
            ORDER BY ip
            LIMIT ? OFFSET ?
        """, (session['start_time'], session['end_time'] or datetime.now().isoformat(), per_page, offset))
        
        hosts = cursor.fetchall()
        
        # Convert to list of dicts for easier use in template
        hosts_list = []
        for host in hosts:
            host_dict = dict(host)
            
            # Get services for this host
            cursor.execute("""
                SELECT s.port, s.service_name
                FROM services s
                WHERE s.host_id = ?
                ORDER BY s.port
            """, (host['id'],))
            host_dict['services'] = cursor.fetchall()
            
            # Get shares for this host
            cursor.execute("""
                SELECT s.share_name
                FROM shares s
                WHERE s.host_id = ?
                ORDER BY s.share_name
            """, (host['id'],))
            host_dict['shares'] = cursor.fetchall()
            
            hosts_list.append(host_dict)
        
        conn.close()
        
        # Create pagination info
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page  # Ceiling division
        }
        
        return render_template(
            'scans/results.html',
            title=f'Results: {job.name}',
            job=job,
            session=session,
            hosts=hosts_list,
            pagination=pagination
        )
        
    except Exception as e:
        current_app.logger.error(f"Error getting scan results: {str(e)}")
        flash(f'Error retrieving scan results: {str(e)}', 'danger')
        return redirect(url_for('scans.view', job_id=job_id))

@scans_bp.route('/<int:job_id>/host/<int:host_id>')
@login_required
def host_details(job_id, host_id):
    """View detailed host information."""
    job = ScanJob.query.get_or_404(job_id)
    
    if job.status != 'completed' or not job.session_id:
        flash('No results available for this scan job.', 'warning')
        return redirect(url_for('scans.view', job_id=job_id))
    
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get host info
        cursor.execute("""
            SELECT * FROM hosts WHERE id = ?
        """, (host_id,))
        
        host = cursor.fetchone()
        if not host:
            flash('Host not found in database.', 'warning')
            return redirect(url_for('scans.results', job_id=job_id))
        
        host_dict = dict(host)
        
        # Get services
        cursor.execute("""
            SELECT port, service_name
            FROM services
            WHERE host_id = ?
            ORDER BY port
        """, (host_id,))
        host_dict['services'] = cursor.fetchall()
        
        # Get shares
        cursor.execute("""
            SELECT share_name
            FROM shares
            WHERE host_id = ?
            ORDER BY share_name
        """, (host_id,))
        host_dict['shares'] = cursor.fetchall()
        
        # Get system info
        cursor.execute("""
            SELECT key, value
            FROM system_info
            WHERE host_id = ?
            ORDER BY key
        """, (host_id,))
        host_dict['system_info'] = cursor.fetchall()
        
        # Get installed software
        cursor.execute("""
            SELECT name, version, path
            FROM installed_software
            WHERE host_id = ?
            ORDER BY name
        """, (host_id,))
        host_dict['installed_software'] = cursor.fetchall()
        
        # Get running services
        cursor.execute("""
            SELECT name, display_name, status
            FROM running_services
            WHERE host_id = ?
            ORDER BY name
        """, (host_id,))
        host_dict['running_services'] = cursor.fetchall()
        
        conn.close()
        
        return render_template(
            'scans/host_details.html',
            title=f'Host Details: {host_dict["ip"]}',
            job=job,
            host=host_dict
        )
        
    except Exception as e:
        current_app.logger.error(f"Error getting host details: {str(e)}")
        flash(f'Error retrieving host details: {str(e)}', 'danger')
        return redirect(url_for('scans.results', job_id=job_id))
