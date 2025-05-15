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
    
    # Debug: Check database structure and content
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        
        # Check tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        current_app.logger.info(f"Database tables: {[t[0] for t in tables]}")
        
        # Check hosts table
        cursor.execute("SELECT COUNT(*) as total FROM hosts")
        total_hosts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as online FROM hosts WHERE status = 'online'")
        online_hosts = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) as offline FROM hosts WHERE status = 'offline'")
        offline_hosts = cursor.fetchone()[0]
        
        current_app.logger.info(f"Hosts: Total={total_hosts}, Online={online_hosts}, Offline={offline_hosts}")
        
        # Check some sample hosts
        cursor.execute("SELECT ip, status, os FROM hosts LIMIT 5")
        sample_hosts = cursor.fetchall()
        current_app.logger.info(f"Sample hosts: {sample_hosts}")
        
        conn.close()
    except Exception as e:
        current_app.logger.error(f"Database debug error: {e}")
    
    # Rest of your existing code...
    running_jobs = get_running_jobs()
    recent_jobs = ScanJob.query.order_by(ScanJob.created_at.desc()).limit(5).all()
    stats = get_db_stats()
    chart_data = get_chart_data()
    
    return render_template(
        'dashboard/index.html',
        title='Dashboard',
        running_jobs=running_jobs,
        recent_jobs=recent_jobs,
        stats=stats,
        chart_data=chart_data
    )

def get_db_stats():
    """Get statistics from the database."""
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        stats = {}
        
        # Count total hosts - now using the hosts table directly
        cursor.execute("SELECT COUNT(*) as count FROM hosts")
        result = cursor.fetchone()
        stats['total_hosts'] = result['count'] if result else 0
        
        # Count online hosts - based on current status
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
        
        # Count top open ports - Fixed to include service names
        cursor.execute("""
            SELECT 
                s.port, 
                CASE 
                    WHEN s.service_name IS NOT NULL AND s.service_name != 'unknown' 
                    THEN s.service_name 
                    ELSE 'unknown' 
                END as service_name,
                COUNT(*) as count
            FROM services s
            JOIN hosts h ON s.ip = h.ip
            WHERE h.status = 'online'
            GROUP BY s.port, service_name
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
    """Get data for dashboard charts with VLAN distribution."""
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get VLAN distribution from current online hosts
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN vlan IS NULL OR vlan = '' THEN 'No VLAN'
                    ELSE 'VLAN ' || vlan
                END as vlan_label,
                COUNT(*) as count
            FROM hosts
            WHERE status = 'online'
            GROUP BY vlan_label
            HAVING count > 0
            ORDER BY count DESC
        """)
        
        vlan_data = cursor.fetchall()
        vlan_labels = []
        vlan_counts = []
        
        if vlan_data:
            for vlan in vlan_data:
                vlan_labels.append(vlan['vlan_label'])
                vlan_counts.append(vlan['count'])
        else:
            # Check if there are any hosts at all
            cursor.execute("SELECT COUNT(*) as count FROM hosts WHERE status = 'online'")
            online_count = cursor.fetchone()['count']
            
            if online_count > 0:
                vlan_labels = ['No VLAN Data']
                vlan_counts = [online_count]
            else:
                vlan_labels = ['No Online Hosts']
                vlan_counts = [1]
        
        # Get OS distribution from current online hosts
        cursor.execute("""
            SELECT 
                CASE
                    WHEN os LIKE '%Windows%' THEN 'Windows'
                    WHEN os LIKE '%Linux%' THEN 'Linux'
                    WHEN os LIKE '%Mac%' OR os LIKE '%OS X%' OR os LIKE '%macOS%' THEN 'macOS'
                    WHEN os LIKE '%Android%' THEN 'Android'
                    WHEN os LIKE '%iOS%' THEN 'iOS'
                    WHEN os IS NOT NULL AND os != '' AND os != 'Unknown' THEN 'Other'
                    ELSE 'Unknown'
                END AS os_group,
                COUNT(*) as count
            FROM hosts
            WHERE status = 'online'
            GROUP BY os_group
            HAVING count > 0
            ORDER BY count DESC
        """)
        
        os_data = cursor.fetchall()
        os_labels = []
        os_counts = []
        
        if os_data:
            for os in os_data:
                os_labels.append(os['os_group'])
                os_counts.append(os['count'])
        else:
            # Check if there are any hosts at all
            cursor.execute("SELECT COUNT(*) as count FROM hosts WHERE status = 'online'")
            online_count = cursor.fetchone()['count']
            
            if online_count > 0:
                os_labels = ['OS Not Detected']
                os_counts = [online_count]
            else:
                os_labels = ['No Online Hosts']
                os_counts = [1]
        
        conn.close()
        
        result = {
            'vlan_distribution': {
                'labels': vlan_labels,
                'counts': vlan_counts
            },
            'os_distribution': {
                'labels': os_labels,
                'counts': os_counts
            }
        }
        
        # Log the result for debugging
        current_app.logger.info(f"VLAN distribution: {dict(zip(vlan_labels, vlan_counts))}")
        current_app.logger.info(f"OS distribution: {dict(zip(os_labels, os_counts))}")
        
        return result
        
    except Exception as e:
        current_app.logger.error(f"Error getting chart data: {str(e)}")
        import traceback
        current_app.logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Return safe default data
        return {
            'vlan_distribution': {
                'labels': ['Error Loading Data'],
                'counts': [1]
            },
            'os_distribution': {
                'labels': ['Error Loading Data'],
                'counts': [1]
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
