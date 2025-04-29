from flask import Blueprint, render_template, current_app, jsonify
from flask_login import login_required
import sqlite3
from app.models import ScanJob
from app.scanning.scanner import get_running_jobs
import json
from datetime import datetime, timedelta

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    """Display dashboard with overview of network discovery data."""
    
    # Get running jobs
    running_jobs = get_running_jobs()
    
    # Get recent scan jobs
    recent_jobs = ScanJob.query.order_by(ScanJob.created_at.desc()).limit(5).all()
    
    # Get statistics from the database
    stats = get_db_stats()
    
    # Get recent scan sessions data for chart
    chart_data = get_chart_data()
    
    return render_template(
        'dashboard/index.html',
        title='Dashboard',
        running_jobs=running_jobs,
        recent_jobs=recent_jobs,
        stats=stats,
        chart_data=json.dumps(chart_data)
    )

def get_db_stats():
    """Get statistics from the database."""
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        stats = {}
        
        # Count total hosts
        cursor.execute("SELECT COUNT(*) as count FROM hosts")
        result = cursor.fetchone()
        stats['total_hosts'] = result['count'] if result else 0
        
        # Count online hosts
        cursor.execute("SELECT COUNT(*) as count FROM hosts WHERE status = 'online'")
        result = cursor.fetchone()
        stats['online_hosts'] = result['count'] if result else 0
        
        # Calculate online percentage
        stats['online_percentage'] = 0
        if stats['total_hosts'] > 0:
            stats['online_percentage'] = (stats['online_hosts'] / stats['total_hosts']) * 100
        
        # Count hosts by OS
        cursor.execute("""
            SELECT os, COUNT(*) as count
            FROM hosts
            WHERE status = 'online' AND os != ''
            GROUP BY os
            ORDER BY count DESC
            LIMIT 5
        """)
        stats['os_distribution'] = cursor.fetchall()
        
        # Count top open ports
        cursor.execute("""
            SELECT port, COUNT(*) as count
            FROM services
            GROUP BY port
            ORDER BY count DESC
            LIMIT 10
        """)
        stats['top_ports'] = cursor.fetchall()
        
        # Count hosts with Foxit license keys
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM system_info
            WHERE key = 'foxit_license_key'
        """)
        result = cursor.fetchone()
        stats['foxit_license_count'] = result['count'] if result else 0
        
        # Count total scan sessions
        cursor.execute("SELECT COUNT(*) as count FROM scan_sessions")
        result = cursor.fetchone()
        stats['scan_sessions'] = result['count'] if result else 0
        
        # Get latest scan session info
        cursor.execute("""
            SELECT id, start_time, end_time, hosts_total, hosts_online, scan_type
            FROM scan_sessions
            ORDER BY id DESC
            LIMIT 1
        """)
        stats['latest_session'] = cursor.fetchone()
        
        conn.close()
        return stats
        
    except Exception as e:
        current_app.logger.error(f"Error getting database stats: {str(e)}")
        return {
            'total_hosts': 0,
            'online_hosts': 0,
            'online_percentage': 0,
            'os_distribution': [],
            'top_ports': [],
            'foxit_license_count': 0,
            'scan_sessions': 0,
            'latest_session': None,
            'error': str(e)
        }
        
def get_chart_data():
    """Get data for dashboard charts with unique host counts."""
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get scan sessions from the last 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        
        cursor.execute("""
            SELECT 
                id,
                start_time,
                hosts_total,
                hosts_online,
                (hosts_online * 100.0 / hosts_total) AS online_percentage
            FROM scan_sessions
            WHERE start_time >= ?
            ORDER BY start_time
        """, (thirty_days_ago,))
        
        sessions = cursor.fetchall()
        
        # Format for Chart.js
        labels = []
        online_hosts = []
        total_hosts = []
        percentages = []
        
        for session in sessions:
            # Convert start_time string to date format MM/DD
            try:
                date_obj = datetime.strptime(session['start_time'], '%Y-%m-%dT%H:%M:%S.%f')
            except ValueError:
                date_obj = datetime.strptime(session['start_time'], '%Y-%m-%dT%H:%M:%S')
            
            labels.append(date_obj.strftime('%m/%d'))
            total_hosts.append(session['hosts_total'])
            online_hosts.append(session['hosts_online'])
            percentages.append(float(session['online_percentage']))
        
        # Get OS distribution for pie chart (unique hosts only)
        cursor.execute("""
            WITH UniqueOnlineHosts AS (
                SELECT ip, MAX(scan_time) as latest_scan_time
                FROM hosts
                WHERE status = 'online'
                GROUP BY ip
            )
            SELECT 
                CASE
                    WHEN os LIKE '%Windows%' THEN 'Windows'
                    WHEN os LIKE '%Linux%' THEN 'Linux'
                    WHEN os LIKE '%Mac%' OR os LIKE '%OS X%' THEN 'macOS'
                    ELSE 'Other'
                END AS os_group,
                COUNT(*) as count
            FROM hosts h
            JOIN UniqueOnlineHosts uoh ON h.ip = uoh.ip AND h.scan_time = uoh.latest_scan_time
            WHERE h.status = 'online' AND h.os != ''
            GROUP BY os_group
            ORDER BY count DESC
        """)
        
        os_data = cursor.fetchall()
        os_labels = []
        os_counts = []
        
        for os in os_data:
            os_labels.append(os['os_group'])
            os_counts.append(os['count'])
        
        conn.close()
        
        return {
            'sessions': {
                'labels': labels,
                'total_hosts': total_hosts,
                'online_hosts': online_hosts,
                'percentages': percentages
            },
            'os_distribution': {
                'labels': os_labels,
                'counts': os_counts
            }
        }
        
    except Exception as e:
        current_app.logger.error(f"Error getting chart data: {str(e)}")
        return {
            'sessions': {
                'labels': [],
                'total_hosts': [],
                'online_hosts': [],
                'percentages': []
            },
            'os_distribution': {
                'labels': [],
                'counts': []
            }
        }
@dashboard_bp.route('/api/dashboard/stats')
@login_required
def get_stats_api():
    """API endpoint to get fresh dashboard statistics."""
    stats = get_db_stats()
    
    # Convert SQLite Row objects to dictionaries for JSON serialization
    if 'os_distribution' in stats and stats['os_distribution']:
        stats['os_distribution'] = [dict(row) for row in stats['os_distribution']]
    
    if 'top_ports' in stats and stats['top_ports']:
        stats['top_ports'] = [dict(row) for row in stats['top_ports']]
    
    if 'latest_session' in stats and stats['latest_session']:
        stats['latest_session'] = dict(stats['latest_session']) if stats['latest_session'] else None
    
    return jsonify(stats)
    
    
@dashboard_bp.route('/api/dashboard/charts')
@login_required
def get_charts_api():
    """API endpoint to get fresh chart data."""
    chart_data = get_chart_data()
    return jsonify(chart_data)
