from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from app.forms import QueryForm, CustomQueryForm
from app.models import SavedQuery
from app.extensions import db
from datetime import datetime
import sqlite3
import json

queries_bp = Blueprint('queries', __name__)

@queries_bp.route('/')
@login_required
def index():
    """Show query interface."""
    # Check if we have a search_ip parameter for looking up hosts
    search_ip = request.args.get('search_ip')
    if search_ip:
        # Look up the host ID for this IP
        try:
            conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Find the most recent entry for this IP
            cursor.execute("""
                SELECT id FROM hosts WHERE ip = ? ORDER BY scan_time DESC LIMIT 1
            """, (search_ip,))
            
            host = cursor.fetchone()
            conn.close()
            
            if host:
                # Redirect to host details
                return redirect(url_for('queries.host_details', host_id=host['id']))
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
    
    if form.validate_on_submit():
        query_name = form.query_type.data
        
        # Build parameters for the query
        params = {}
        if query_name == 'hosts_with_port' and form.port.data:
            params['port'] = form.port.data
        elif query_name == 'hosts_with_software' and form.software.data:
            params['software'] = f'%{form.software.data}%'
        
        results = run_predefined_query(query_name, params)
        
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
        saved_queries=saved_queries
    )

@queries_bp.route('/custom', methods=['GET', 'POST'])
@login_required
def custom():
    """Run custom SQL queries."""
    form = CustomQueryForm()
    results = []
    error = None
    
    if form.validate_on_submit():
        try:
            results = run_custom_query(form.sql_query.data)
            
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
        saved_queries=saved_queries
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
    
    try:
        if query.query_type == 'predefined':
            params = query.get_parameters()
            results = run_predefined_query(query.query_key, params)
        else:
            results = run_custom_query(query.sql_query)
        
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
            ).all()
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
            ).all()
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
    """Export query results to CSV."""
    query_type = request.form.get('query_type')
    query_data = request.form.get('query_data')
    
    if not query_type or not query_data:
        flash('Invalid export request.', 'danger')
        return redirect(url_for('queries.index'))
    
    try:
        results = []
        if query_type == 'predefined':
            # Parse the query data
            data = json.loads(query_data)
            results = run_predefined_query(data['key'], data.get('params', {}))
        else:
            results = run_custom_query(query_data)
        
        if not results:
            flash('No results to export.', 'warning')
            return redirect(url_for('queries.index'))
        
        # Generate CSV content
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header row
        writer.writerow(results[0].keys())
        
        # Write data rows
        for row in results:
            writer.writerow(row.values())
        
        csv_data = output.getvalue()
        
        # Send as downloadable file
        from flask import Response
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment;filename=network_query_{timestamp}.csv'
            }
        )
        
    except Exception as e:
        flash(f'Error exporting results: {str(e)}', 'danger')
        return redirect(url_for('queries.index'))

@queries_bp.route('/host/<int:host_id>')
@login_required
def host_details(host_id):
    """View detailed host information from query results."""
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
            return redirect(url_for('queries.index'))
        
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
            'queries/host_details.html',
            title=f'Host Details: {host_dict["ip"]}',
            host=host_dict,
            from_query=True
        )
        
    except Exception as e:
        current_app.logger.error(f"Error getting host details: {str(e)}")
        flash(f'Error retrieving host details: {str(e)}', 'danger')
        return redirect(url_for('queries.index'))

def run_predefined_query(query_name, params=None):
    """
    Execute a predefined query against the database.
    
    Args:
        query_name (str): Name of the query in SAMPLE_QUERIES
        params (dict): Parameters for the query
        
    Returns:
        list: Query results as a list of dictionaries
    """
    if params is None:
        params = {}
    
    try:
        conn = sqlite3.connect(current_app.config['DATABASE_PATH'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Define predefined queries
        queries = {
            'online_hosts': {
                'sql': """
                    WITH LatestHosts AS (
                        SELECT ip, MAX(scan_time) as latest_scan_time
                        FROM hosts
                        WHERE status = 'online'
                        GROUP BY ip
                    )
                    SELECT h.id, h.ip, h.hostname, h.os, h.mac_address, h.scan_time
                    FROM hosts h
                    JOIN LatestHosts lh ON h.ip = lh.ip AND h.scan_time = lh.latest_scan_time
                    WHERE h.status = 'online'
                    ORDER BY h.ip
                """,
                'params': []
            },
            'hosts_with_port': {
                'sql': """
                    SELECT h.id, h.ip, h.hostname, h.os, s.port, s.service_name
                    FROM hosts h
                    JOIN services s ON h.id = s.host_id
                    WHERE s.port = ? AND h.status = 'online'
                    ORDER BY h.ip
                """,
                'params': [params.get('port', 0)]
            },
            'hosts_with_software': {
                'sql': """
                    SELECT h.id, h.ip, h.hostname, h.os, i.name, i.version
                    FROM hosts h
                    JOIN installed_software i ON h.id = i.host_id
                    WHERE i.name LIKE ? AND h.status = 'online'
                    ORDER BY h.ip
                """,
                'params': [params.get('software', '%')]
            },
            'hosts_with_foxit': {
                'sql': """
                    SELECT h.id, h.ip, h.hostname, h.os, si.value AS foxit_license_key
                    FROM hosts h
                    JOIN system_info si ON h.id = si.host_id
                    WHERE si.key = 'foxit_license_key' AND h.status = 'online'
                    ORDER BY h.ip
                """,
                'params': []
            },
            'scan_sessions': {
                'sql': """
                    SELECT id, start_time, end_time, target_range, hosts_total, hosts_online,
                           (hosts_online * 100.0 / hosts_total) AS online_percentage,
                           scan_type
                    FROM scan_sessions
                    ORDER BY start_time DESC
                """,
                'params': []
            },
            'windows_hosts': {
                'sql': """
                    SELECT h.id, h.ip, h.hostname, h.os, h.mac_address, h.scan_time
                    FROM hosts h
                    WHERE h.status = 'online' AND 
                          (h.os LIKE '%Windows%' OR h.os LIKE '%Microsoft%')
                    ORDER BY h.ip
                """,
                'params': []
            },
            'linux_hosts': {
                'sql': """
                    SELECT h.id, h.ip, h.hostname, h.os, h.mac_address, h.scan_time
                    FROM hosts h
                    WHERE h.status = 'online' AND 
                          (h.os LIKE '%Linux%' OR h.os LIKE '%Ubuntu%' OR h.os LIKE '%Debian%')
                    ORDER BY h.ip
                """,
                'params': []
            },
            'hosts_with_admin_shares': {
                'sql': """
                    SELECT h.id, h.ip, h.hostname, h.os, s.share_name
                    FROM hosts h
                    JOIN shares s ON h.id = s.host_id
                    WHERE h.status = 'online' AND
                          (s.share_name = 'C$' OR s.share_name = 'ADMIN$' OR s.share_name = 'IPC$')
                    ORDER BY h.ip, s.share_name
                """,
                'params': []
            }
        }
        
        if query_name not in queries:
            raise ValueError(f"Unknown predefined query: {query_name}")
        
        query = queries[query_name]
        cursor.execute(query['sql'], query['params'])
        results = cursor.fetchall()
        
        # Convert to list of dicts
        result_list = [dict(row) for row in results]
        
        conn.close()
        return result_list
    
    except Exception as e:
        current_app.logger.error(f"Error running predefined query: {str(e)}")
        raise

def run_custom_query(sql_query):
    """Run a custom SQL query."""
    try:
        # Basic SQL injection protection - block dangerous operations
        sql_lower = sql_query.lower()
        forbidden_commands = ['drop', 'delete', 'update', 'insert', 'create', 'alter', 'pragma', 'attach']
        
        for cmd in forbidden_commands:
            if cmd in sql_lower:
                raise ValueError(f"SQL query contains forbidden command: {cmd}")
        
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
