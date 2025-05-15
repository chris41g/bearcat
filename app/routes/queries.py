# app/routes/queries.py - Enhanced version with unlimited results and improved CSV export
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, Response
from flask_login import login_required, current_user
from app.forms import QueryForm, CustomQueryForm
from app.models import SavedQuery
from app.extensions import db
from datetime import datetime, timedelta
import sqlite3
import json
import ipaddress
import re
import csv
import io

queries_bp = Blueprint('queries', __name__)

# Configuration for result limits
MAX_DISPLAY_RESULTS = 500  # Maximum results to display in browser
AUTO_CSV_THRESHOLD = 250   # Automatically offer CSV download if more than this many results

@queries_bp.route('/')
@login_required
def index():
    """Show query interface."""
    # Check if we have a search_ip parameter for looking up hosts
    search_ip = request.args.get('search_ip')
    if search_ip:
        # Look up the host by IP directly
        try:
            conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find the IP in the hosts table
            cursor.execute("""
                SELECT ip FROM hosts WHERE ip = ?
            """, (search_ip,))
            
            host = cursor.fetchone()
            conn.close()
            
            if host:
                # Redirect to host details - now using IP as parameter instead of host_id
                return redirect(url_for('queries.host_details', ip=host['ip']))
            else:
                flash(f'No host found with IP: {search_ip}', 'warning')
        except Exception as e:
            flash(f'Error looking up host: {str(e)}', 'danger')
    
    # Regular rendering if no search_ip or if lookup failed
    return render_template('queries/index.html', title='Query Database')

@queries_bp.route('/predefined', methods=['GET', 'POST'])
@login_required
def predefined():
    """Run predefined queries."""
    form = QueryForm()
    results = []
    query_name = None
    error = None
    total_count = 0
    is_truncated = False
    
    if form.validate_on_submit():
        query_name = form.query_type.data
        
        # Build parameters for the query
        params = {}
        
        if query_name == 'hosts_with_port' and form.port.data:
            params['port'] = form.port.data
        elif query_name == 'hosts_with_software' and form.software.data:
            params['software'] = f'%{form.software.data}%'
        elif query_name == 'hosts_by_ip' and form.ip_search.data:
            params['ip_search'] = form.ip_search.data
        elif query_name == 'hosts_by_os' and form.os_filter.data:
            params['os_filter'] = f'%{form.os_filter.data}%'
        elif query_name == 'hosts_with_shares' and form.share_name.data:
            params['share_name'] = f'%{form.share_name.data}%'
        elif query_name == 'recent_scans' and form.days.data:
            params['days'] = form.days.data
        
        try:
            # Get count first to determine if we need to limit results
            total_count = get_query_count(query_name, params)
            
            # Get results (limited for display)
            results = run_predefined_query(query_name, params, limit_for_display=True)
            
            # Check if results were truncated
            is_truncated = total_count > MAX_DISPLAY_RESULTS
            
        except Exception as e:
            error = str(e)
            current_app.logger.error(f"Error running predefined query {query_name}: {str(e)}")
        
        # Update last run time if this is a saved query
        saved_query = SavedQuery.query.filter_by(
            query_type='predefined',
            query_key=query_name,
            created_by=current_user.id
        ).first()
        
        if saved_query:
            saved_query.last_run = datetime.now()
            db.session.commit()
    
    # Get list of saved queries
    saved_queries = SavedQuery.query.filter_by(
        query_type='predefined',
        created_by=current_user.id
    ).all()
    
    return render_template(
        'queries/predefined.html',
        title='Predefined Queries',
        form=form,
        results=results,
        query_name=query_name,
        error=error,
        saved_queries=saved_queries,
        total_count=total_count,
        is_truncated=is_truncated,
        max_display=MAX_DISPLAY_RESULTS,
        auto_csv_threshold=AUTO_CSV_THRESHOLD
    )

@queries_bp.route('/custom', methods=['GET', 'POST'])
@login_required
def custom():
    """Run custom SQL queries."""
    form = CustomQueryForm()
    results = []
    error = None
    total_count = 0
    is_truncated = False
    
    if form.validate_on_submit():
        try:
            # Get count first
            total_count = get_custom_query_count(form.sql_query.data)
            
            # Get results (limited for display)
            results = run_custom_query(form.sql_query.data, limit_for_display=True)
            
            # Check if results were truncated
            is_truncated = total_count > MAX_DISPLAY_RESULTS
            
            # Save the query if requested
            if form.save_query.data and form.query_name.data:
                saved_query = SavedQuery(
                    name=form.query_name.data,
                    description=f"Custom query created on {datetime.now().strftime('%Y-%m-%d')}",
                    query_type='custom',
                    sql_query=form.sql_query.data,
                    created_by=current_user.id,
                    last_run=datetime.now()
                )
                db.session.add(saved_query)
                db.session.commit()
                flash(f'Query "{form.query_name.data}" saved successfully.', 'success')
        except Exception as e:
            error = str(e)
    
    # Get list of saved custom queries
    saved_queries = SavedQuery.query.filter_by(
        query_type='custom',
        created_by=current_user.id
    ).all()
    
    return render_template(
        'queries/custom.html',
        title='Custom SQL Queries',
        form=form,
        results=results,
        error=error,
        saved_queries=saved_queries,
        total_count=total_count,
        is_truncated=is_truncated,
        max_display=MAX_DISPLAY_RESULTS,
        auto_csv_threshold=AUTO_CSV_THRESHOLD
    )

@queries_bp.route('/saved/<int:query_id>')
@login_required
def run_saved(query_id):
    """Run a saved query."""
    query = SavedQuery.query.get_or_404(query_id)
    
    # Check if user owns this query
    if query.created_by != current_user.id:
        flash('You do not have permission to run this query.', 'danger')
        return redirect(url_for('queries.index'))
    
    results = []
    error = None
    total_count = 0
    is_truncated = False
    
    try:
        if query.query_type == 'predefined':
            params = query.get_parameters()
            total_count = get_query_count(query.query_key, params)
            results = run_predefined_query(query.query_key, params, limit_for_display=True)
        else:
            total_count = get_custom_query_count(query.sql_query)
            results = run_custom_query(query.sql_query, limit_for_display=True)
        
        # Check if results were truncated
        is_truncated = total_count > MAX_DISPLAY_RESULTS
        
        # Update last run time
        query.last_run = datetime.now()
        db.session.commit()
    except Exception as e:
        error = str(e)
    
    # Determine which template to use
    if query.query_type == 'predefined':
        return render_template(
            'queries/predefined.html',
            title=f'Saved Query: {query.name}',
            form=QueryForm(),
            results=results,
            query_name=query.query_key,
            error=error,
            saved_queries=SavedQuery.query.filter_by(
                query_type='predefined',
                created_by=current_user.id
            ).all(),
            total_count=total_count,
            is_truncated=is_truncated,
            max_display=MAX_DISPLAY_RESULTS,
            auto_csv_threshold=AUTO_CSV_THRESHOLD
        )
    else:
        return render_template(
            'queries/custom.html',
            title=f'Saved Query: {query.name}',
            form=CustomQueryForm(sql_query=query.sql_query),
            results=results,
            error=error,
            saved_queries=SavedQuery.query.filter_by(
                query_type='custom',
                created_by=current_user.id
            ).all(),
            total_count=total_count,
            is_truncated=is_truncated,
            max_display=MAX_DISPLAY_RESULTS,
            auto_csv_threshold=AUTO_CSV_THRESHOLD
        )

@queries_bp.route('/saved/<int:query_id>/delete', methods=['POST'])
@login_required
def delete_saved(query_id):
    """Delete a saved query."""
    query = SavedQuery.query.get_or_404(query_id)
    
    # Check if user owns this query
    if query.created_by != current_user.id:
        flash('You do not have permission to delete this query.', 'danger')
        return redirect(url_for('queries.index'))
    
    query_name = query.name
    query_type = query.query_type
    db.session.delete(query)
    db.session.commit()
    
    flash(f'Query "{query_name}" deleted.', 'success')
    
    if query_type == 'predefined':
        return redirect(url_for('queries.predefined'))
    else:
        return redirect(url_for('queries.custom'))

@queries_bp.route('/export', methods=['POST'])
@login_required
def export_results():
    """Export query results to CSV - now supports unlimited results."""
    query_type = request.form.get('query_type')
    query_data = request.form.get('query_data')
    
    if not query_type or not query_data:
        flash('Invalid export request.', 'danger')
        return redirect(url_for('queries.index'))
    
    try:
        results = []
        filename_prefix = "network_query"
        
        if query_type == 'predefined':
            # Parse the query data
            data = json.loads(query_data)
            results = run_predefined_query(data['key'], data.get('params', {}), limit_for_display=False)
            filename_prefix = f"network_{data['key']}"
        else:
            results = run_custom_query(query_data, limit_for_display=False)
            filename_prefix = "network_custom_query"
        
        if not results:
            flash('No results to export.', 'warning')
            return redirect(url_for('queries.index'))
        
        # Generate CSV content
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header row
        writer.writerow(results[0].keys())
        
        # Write data rows
        for row in results:
            writer.writerow(row.values())
        
        csv_data = output.getvalue()
        
        # Send as downloadable file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{filename_prefix}_{timestamp}.csv"
        
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment;filename={filename}',
                'X-Total-Records': str(len(results))
            }
        )
        
    except Exception as e:
        current_app.logger.error(f"Error exporting results: {str(e)}")
        flash(f'Error exporting results: {str(e)}', 'danger')
        return redirect(url_for('queries.index'))

@queries_bp.route('/export_unlimited', methods=['POST'])
@login_required
def export_unlimited():
    """Export unlimited query results directly - for large result sets."""
    query_type = request.form.get('query_type')
    query_data = request.form.get('query_data')
    
    if not query_type or not query_data:
        flash('Invalid export request.', 'danger')
        return redirect(url_for('queries.index'))
    
    try:
        # Get the current app for the generator function
        app = current_app._get_current_object()
        
        # Create a streaming response for large datasets
        def generate_csv():
            with app.app_context():
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Get results without limit
                if query_type == 'predefined':
                    data = json.loads(query_data)
                    results = run_predefined_query(data['key'], data.get('params', {}), limit_for_display=False)
                    filename_prefix = f"network_{data['key']}"
                else:
                    results = run_custom_query(query_data, limit_for_display=False)
                    filename_prefix = "network_custom_query"
                
                if results:
                    # Write header
                    writer.writerow(results[0].keys())
                    yield output.getvalue()
                    output.seek(0)
                    output.truncate(0)
                    
                    # Write data rows in chunks
                    for i, row in enumerate(results):
                        writer.writerow(row.values())
                        
                        # Yield every 100 rows to avoid memory issues
                        if i % 100 == 0:
                            yield output.getvalue()
                            output.seek(0)
                            output.truncate(0)
                    
                    # Yield any remaining data
                    if output.getvalue():
                        yield output.getvalue()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"network_unlimited_{timestamp}.csv"
        
        return Response(
            generate_csv(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment;filename={filename}',
                'X-Export-Type': 'unlimited'
            }
        )
        
    except Exception as e:
        current_app.logger.error(f"Error in unlimited export: {str(e)}")
        flash(f'Error exporting unlimited results: {str(e)}', 'danger')
        return redirect(url_for('queries.index'))

@queries_bp.route('/host/<ip>')
@login_required
def host_details(ip):
    """View detailed host information from query results."""
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get host info using IP directly
        cursor.execute("""
            SELECT * FROM hosts WHERE ip = ?
        """, (ip,))
        
        host = cursor.fetchone()
        if not host:
            flash('Host not found in database.', 'warning')
            return redirect(url_for('queries.index'))
        
        host_dict = dict(host)
        
        # Get services
        cursor.execute("""
            SELECT port, service_name
            FROM services
            WHERE ip = ?
            ORDER BY port
        """, (ip,))
        host_dict['services'] = cursor.fetchall()
        
        # Get shares
        cursor.execute("""
            SELECT share_name
            FROM shares
            WHERE ip = ?
            ORDER BY share_name
        """, (ip,))
        host_dict['shares'] = cursor.fetchall()
        
        # Get system info
        cursor.execute("""
            SELECT key, value
            FROM system_info
            WHERE ip = ?
            ORDER BY key
        """, (ip,))
        host_dict['system_info'] = cursor.fetchall()
        
        # Get installed software
        cursor.execute("""
            SELECT name, version, path
            FROM installed_software
            WHERE ip = ?
            ORDER BY name
        """, (ip,))
        host_dict['installed_software'] = cursor.fetchall()
        
        # Get running services
        cursor.execute("""
            SELECT name, display_name, status
            FROM running_services
            WHERE ip = ?
            ORDER BY name
        """, (ip,))
        host_dict['running_services'] = cursor.fetchall()
        
        # Get scan history
        cursor.execute("""
            SELECT scan_time, status, session_id
            FROM scan_history
            WHERE ip = ?
            ORDER BY scan_time DESC
            LIMIT 10
        """, (ip,))
        host_dict['scan_history'] = cursor.fetchall()
        
        conn.close()
        
        return render_template(
            'queries/host_details.html',
            title=f'Host Details: {host_dict["ip"]}',
            host=host_dict,
            from_query=True
        )
        
    except Exception as e:
        current_app.logger.error(f"Error getting host details: {str(e)}")
        flash(f'Error retrieving host details: {str(e)}', 'danger')
        return redirect(url_for('queries.index'))

def convert_wildcard_to_sql(wildcard_pattern):
    """Convert wildcard pattern to SQL LIKE pattern and WHERE clause"""
    if not wildcard_pattern:
        return None, []
    
    # Handle wildcards
    if '*' in wildcard_pattern or '?' in wildcard_pattern:
        # Convert wildcards to SQL LIKE pattern
        sql_pattern = wildcard_pattern.replace('*', '%').replace('?', '_')
        return "ip LIKE ?", [sql_pattern]
    
    # Try to parse as single IP
    try:
        ipaddress.ip_address(wildcard_pattern)
        return "ip = ?", [wildcard_pattern]
    except ValueError:
        pass
    
    # Try to parse as subnet
    try:
        network = ipaddress.ip_network(wildcard_pattern, strict=False)
        # For subnet queries, we need to check if IP is in range
        network_addr = str(network.network_address)
        broadcast_addr = str(network.broadcast_address)
        return "ip BETWEEN ? AND ?", [network_addr, broadcast_addr]
    except ValueError:
        pass
    
    # Try to parse as range
    if '-' in wildcard_pattern:
        try:
            start_ip, end_ip = wildcard_pattern.split('-', 1)
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            ipaddress.ip_address(start_ip)
            ipaddress.ip_address(end_ip)
            return "ip BETWEEN ? AND ?", [start_ip, end_ip]
        except (ValueError, AttributeError):
            pass
    
    # If nothing else works, treat as text search
    return "ip LIKE ?", [f'%{wildcard_pattern}%']

def get_query_count(query_name, params=None):
    """Get count of results for a predefined query."""
    if params is None:
        params = {}
    
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        
        # Build COUNT queries for each predefined query type
        if query_name == 'online_hosts':
            cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = 'online'")
            
        elif query_name == 'hosts_with_port':
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts h
                JOIN services s ON h.ip = s.ip
                WHERE s.port = ? AND h.status = 'online'
            """, [params.get('port', 0)])
            
        elif query_name == 'hosts_with_software':
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts h
                JOIN installed_software i ON h.ip = i.ip
                WHERE i.name LIKE ? AND h.status = 'online'
            """, [params.get('software', '%')])
            
        elif query_name == 'hosts_with_foxit':
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts h
                JOIN system_info si ON h.ip = si.ip
                WHERE si.key = 'foxit_license_key' AND h.status = 'online'
            """)
            
        elif query_name == 'foxit_without_license':
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts h
                JOIN installed_software s ON h.ip = s.ip
                WHERE (s.name LIKE '%Foxit%' OR s.name LIKE '%PDF%Editor%')
                AND h.ip NOT IN (
                    SELECT ip 
                    FROM system_info 
                    WHERE key = 'foxit_license_key' AND value IS NOT NULL AND value != ''
                )
                AND h.status = 'online'
            """)
            
        elif query_name == 'foxit_all_installs':
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts h
                JOIN installed_software s ON h.ip = s.ip
                WHERE (s.name LIKE '%Foxit%' OR s.name LIKE '%PDF%Editor%')
                AND h.status = 'online'
            """)
            
        elif query_name == 'hosts_by_ip':
            ip_search = params.get('ip_search', '')
            where_clause, query_params = convert_wildcard_to_sql(ip_search)
            
            if where_clause:
                query = f"SELECT COUNT(*) FROM hosts WHERE {where_clause}"
                cursor.execute(query, query_params)
            else:
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE 1=0")
                
        elif query_name == 'hosts_by_os':
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts
                WHERE status = 'online' AND os LIKE ?
            """, [params.get('os_filter', '%')])
            
        elif query_name == 'hosts_with_shares':
            share_filter = params.get('share_name', '')
            if share_filter:
                cursor.execute("""
                    SELECT COUNT(DISTINCT h.ip)
                    FROM hosts h
                    JOIN shares s ON h.ip = s.ip
                    WHERE h.status = 'online' AND s.share_name LIKE ?
                """, [share_filter])
            else:
                cursor.execute("""
                    SELECT COUNT(DISTINCT h.ip)
                    FROM hosts h
                    JOIN shares s ON h.ip = s.ip
                    WHERE h.status = 'online'
                """)
                
        elif query_name == 'hosts_with_admin_shares':
            cursor.execute("""
                SELECT COUNT(DISTINCT h.ip)
                FROM hosts h
                JOIN shares s ON h.ip = s.ip
                WHERE h.status = 'online' AND 
                      (s.share_name = 'C$' OR s.share_name = 'ADMIN$' OR s.share_name = 'IPC$')
            """)
            
        elif query_name == 'windows_hosts':
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts
                WHERE status = 'online' AND 
                      (os LIKE '%Windows%' OR os LIKE '%Microsoft%')
            """)
            
        elif query_name == 'linux_hosts':
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts
                WHERE status = 'online' AND 
                      (os LIKE '%Linux%' OR os LIKE '%Ubuntu%' OR os LIKE '%Debian%' OR os LIKE '%Red Hat%' OR os LIKE '%CentOS%')
            """)
            
        elif query_name == 'recent_scans':
            days = params.get('days', 7)
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("""
                SELECT COUNT(*)
                FROM hosts h
                WHERE h.last_seen >= ?
            """, [cutoff_date])
            
        elif query_name == 'scan_sessions':
            cursor.execute("SELECT COUNT(*) FROM scan_sessions")
            
        else:
            return 0
        
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else 0
        
    except Exception as e:
        current_app.logger.error(f"Error getting query count: {str(e)}")
        return 0

def get_custom_query_count(sql_query):
    """Get count of results for a custom query."""
    try:
        # Convert the query to a COUNT query
        # This is a simple approach - wrap the original query in a COUNT
        sql_lower = sql_query.lower().strip()
        
        # Basic SQL injection protection
        forbidden_commands = ['drop', 'delete', 'update', 'insert', 'create', 'alter', 'pragma', 'attach']
        for cmd in forbidden_commands:
            if cmd in sql_lower:
                raise ValueError(f"SQL query contains forbidden command: {cmd}")
        
        # Wrap query in COUNT
        count_query = f"SELECT COUNT(*) FROM ({sql_query})"
        
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        cursor = conn.cursor()
        cursor.execute(count_query)
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else 0
        
    except Exception as e:
        current_app.logger.error(f"Error getting custom query count: {str(e)}")
        # If count fails, run the original query and count results
        # This is less efficient but more reliable
        try:
            results = run_custom_query(sql_query, limit_for_display=False)
            return len(results)
        except:
            return 0

def run_predefined_query(query_name, params=None, limit_for_display=True):
    """
    Execute a predefined query against the database.
    
    Args:
        query_name (str): Name of the query
        params (dict): Parameters for the query
        limit_for_display (bool): Whether to limit results for display purposes
        
    Returns:
        list: Query results as a list of dictionaries
    """
    if params is None:
        params = {}
    
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Add LIMIT clause if limiting for display
        limit_clause = f" LIMIT {MAX_DISPLAY_RESULTS}" if limit_for_display else ""
        
        # Define predefined queries for new schema
        if query_name == 'online_hosts':
            cursor.execute(f"""
                SELECT ip, hostname, os, mac_address, vlan, last_seen
                FROM hosts 
                WHERE status = 'online'
                ORDER BY ip{limit_clause}
            """)
            
        elif query_name == 'hosts_with_port':
            cursor.execute(f"""
                SELECT h.ip, h.hostname, h.os, s.port, s.service_name
                FROM hosts h
                JOIN services s ON h.ip = s.ip
                WHERE s.port = ? AND h.status = 'online'
                ORDER BY h.ip{limit_clause}
            """, [params.get('port', 0)])
            
        elif query_name == 'hosts_with_software':
            cursor.execute(f"""
                SELECT h.ip, h.hostname, h.os, i.name, i.version
                FROM hosts h
                JOIN installed_software i ON h.ip = i.ip
                WHERE i.name LIKE ? AND h.status = 'online'
                ORDER BY h.ip{limit_clause}
            """, [params.get('software', '%')])
            
        elif query_name == 'hosts_with_foxit':
            cursor.execute(f"""
                SELECT h.ip, h.hostname, h.os, si.value AS foxit_license_key
                FROM hosts h
                JOIN system_info si ON h.ip = si.ip
                WHERE si.key = 'foxit_license_key' AND h.status = 'online'
                ORDER BY h.ip{limit_clause}
            """)
            
        elif query_name == 'foxit_without_license':
            cursor.execute(f"""
                SELECT h.ip, h.hostname, h.os, 
                       s.name AS foxit_product, 
                       s.version AS foxit_version,
                       s.path AS installation_path
                FROM hosts h
                JOIN installed_software s ON h.ip = s.ip
                WHERE (s.name LIKE '%Foxit%' OR s.name LIKE '%PDF%Editor%')
                AND h.ip NOT IN (
                    SELECT ip 
                    FROM system_info 
                    WHERE key = 'foxit_license_key' AND value IS NOT NULL AND value != ''
                )
                AND h.status = 'online'
                ORDER BY h.ip, s.name{limit_clause}
            """)
            
        elif query_name == 'foxit_all_installs':
            cursor.execute(f"""
                SELECT 
                    h.ip, 
                    h.hostname, 
                    h.os, 
                    s.name AS foxit_product, 
                    s.version AS foxit_version,
                    s.path AS installation_path,
                    CASE 
                        WHEN si.value IS NOT NULL AND si.value != '' THEN si.value
                        ELSE 'No License Key'
                    END AS license_key
                FROM hosts h
                JOIN installed_software s ON h.ip = s.ip
                LEFT JOIN system_info si ON h.ip = si.ip AND si.key = 'foxit_license_key'
                WHERE (s.name LIKE '%Foxit%' OR s.name LIKE '%PDF%Editor%')
                AND h.status = 'online'
                ORDER BY h.ip, s.name{limit_clause}
            """)
            
        elif query_name == 'hosts_by_ip':
            # Handle IP/subnet/range/wildcard search
            ip_search = params.get('ip_search', '')
            where_clause, query_params = convert_wildcard_to_sql(ip_search)
            
            if where_clause:
                query = f"""
                    SELECT ip, hostname, os, mac_address, status, last_seen
                    FROM hosts
                    WHERE {where_clause}
                    ORDER BY ip{limit_clause}
                """
                cursor.execute(query, query_params)
            else:
                # If no valid search pattern, return empty result
                cursor.execute("SELECT ip FROM hosts WHERE 1=0")
                
        elif query_name == 'hosts_by_os':
            cursor.execute(f"""
                SELECT ip, hostname, os, mac_address, status, last_seen
                FROM hosts
                WHERE status = 'online' AND os LIKE ?
                ORDER BY ip{limit_clause}
            """, [params.get('os_filter', '%')])
            
        elif query_name == 'hosts_with_shares':
            share_filter = params.get('share_name', '')
            if share_filter:
                cursor.execute(f"""
                    SELECT DISTINCT h.ip, h.hostname, h.os, s.share_name
                    FROM hosts h
                    JOIN shares s ON h.ip = s.ip
                    WHERE h.status = 'online' AND s.share_name LIKE ?
                    ORDER BY h.ip, s.share_name{limit_clause}
                """, [share_filter])
            else:
                cursor.execute(f"""
                    SELECT DISTINCT h.ip, h.hostname, h.os, 
                           GROUP_CONCAT(s.share_name, ', ') as shares
                    FROM hosts h
                    JOIN shares s ON h.ip = s.ip
                    WHERE h.status = 'online'
                    GROUP BY h.ip, h.hostname, h.os
                    ORDER BY h.ip{limit_clause}
                """)
                
        elif query_name == 'hosts_with_admin_shares':
            cursor.execute(f"""
                SELECT h.ip, h.hostname, h.os, s.share_name
                FROM hosts h
                JOIN shares s ON h.ip = s.ip
                WHERE h.status = 'online' AND 
                      (s.share_name = 'C OR s.share_name = 'ADMIN OR s.share_name = 'IPC)
                ORDER BY h.ip, s.share_name{limit_clause}
            """)
            
        elif query_name == 'windows_hosts':
            cursor.execute(f"""
                SELECT ip, hostname, os, mac_address, vlan, last_seen
                FROM hosts
                WHERE status = 'online' AND 
                      (os LIKE '%Windows%' OR os LIKE '%Microsoft%')
                ORDER BY ip{limit_clause}
            """)
            
        elif query_name == 'linux_hosts':
            cursor.execute(f"""
                SELECT ip, hostname, os, mac_address, vlan, last_seen
                FROM hosts
                WHERE status = 'online' AND 
                      (os LIKE '%Linux%' OR os LIKE '%Ubuntu%' OR os LIKE '%Debian%' OR os LIKE '%Red Hat%' OR os LIKE '%CentOS%')
                ORDER BY ip{limit_clause}
            """)
            
        elif query_name == 'recent_scans':
            days = params.get('days', 7)
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(f"""
                SELECT h.ip, h.hostname, h.os, h.status, h.last_seen
                FROM hosts h
                WHERE h.last_seen >= ?
                ORDER BY h.last_seen DESC, h.ip{limit_clause}
            """, [cutoff_date])
            
        elif query_name == 'scan_sessions':
            cursor.execute(f"""
                SELECT id, start_time, end_time, target_range, hosts_total, hosts_online,
                       (hosts_online * 100.0 / hosts_total) AS online_percentage,
                       scan_type
                FROM scan_sessions
                ORDER BY start_time DESC{limit_clause}
            """)
            
        else:
            raise ValueError(f"Unknown predefined query: {query_name}")
        
        results = cursor.fetchall()
        
        # Convert to list of dicts
        result_list = [dict(row) for row in results]
        
        conn.close()
        return result_list
    
    except Exception as e:
        current_app.logger.error(f"Error running predefined query: {str(e)}")
        raise

def run_custom_query(sql_query, limit_for_display=True):
    """Run a custom SQL query with optional limiting."""
    try:
        # Basic SQL injection protection - block dangerous operations
        sql_lower = sql_query.lower()
        forbidden_commands = ['drop', 'delete', 'update', 'insert', 'create', 'alter', 'pragma', 'attach']
        
        for cmd in forbidden_commands:
            if cmd in sql_lower:
                raise ValueError(f"SQL query contains forbidden command: {cmd}")
        
        # Add LIMIT if requested and not already present
        if limit_for_display and 'limit' not in sql_lower:
            sql_query = f"{sql_query.rstrip(';')} LIMIT {MAX_DISPLAY_RESULTS}"
        
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(sql_query)
        results = cursor.fetchall()
        
        # Convert to list of dicts
        result_list = [dict(row) for row in results]
        
        conn.close()
        return result_list
    
    except Exception as e:
        current_app.logger.error(f"Error running custom query: {str(e)}")
        raise
