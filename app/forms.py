from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, IPAddress, Optional, NumberRange, Length
import ipaddress

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class ScanForm(FlaskForm):
    name = StringField('Scan Name', validators=[DataRequired(), Length(max=100)])
    
    target_type = SelectField('Target Type', 
                             choices=[('subnet', 'Subnet (CIDR)'), 
                                      ('range', 'IP Range'), 
                                      ('target', 'Single IP'), 
                                      ('local', 'Local Networks')],
                             validators=[DataRequired()])
    
    target = StringField('Target', validators=[Length(max=100)])
    
    scan_type = SelectField('Scan Type', 
                           choices=[('basic', 'Basic (Fast)'), 
                                    ('full', 'Full (Detailed)')],
                           validators=[DataRequired()])
    
    workers = IntegerField('Workers', 
                          default=50, 
                          validators=[NumberRange(min=1, max=500)])
    
    username = StringField('Windows Username (Optional)', validators=[Optional(), Length(max=100)])
    password = PasswordField('Windows Password (Optional)', validators=[Optional()])
    
    find_foxit = BooleanField('Search for Foxit PDF License Keys')
    
    submit = SubmitField('Start Scan')
    
    def validate_target(self, field):
        # Skip validation if local networks is selected
        if self.target_type.data == 'local':
            return
        
        # Target is required for other scan types
        if not field.data:
            raise ValidationError('Target is required')
        
        if self.target_type.data == 'subnet':
            try:
                ipaddress.ip_network(field.data, strict=False)
            except ValueError:
                raise ValidationError('Invalid subnet format. Use CIDR notation (e.g., 192.168.1.0/24)')
        
        elif self.target_type.data == 'range':
            try:
                start, end = field.data.split('-')
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                
                if start_ip.version != end_ip.version:
                    raise ValidationError('IP range must use same IP version')
                
                if int(start_ip) > int(end_ip):
                    raise ValidationError('Start IP must be less than or equal to end IP')
            except ValueError:
                raise ValidationError('Invalid IP range format. Use format: 192.168.1.1-192.168.1.254')
        
        elif self.target_type.data == 'target':
            try:
                ipaddress.ip_address(field.data)
            except ValueError:
                raise ValidationError('Invalid IP address')

class QueryForm(FlaskForm):
    query_type = SelectField('Query Type', 
                            choices=[('online_hosts', 'All Online Hosts'),
                                     ('hosts_with_port', 'Hosts with Specific Port'),
                                     ('hosts_with_software', 'Hosts with Specific Software'),
                                     ('hosts_with_foxit', 'Hosts with Foxit License'),
                                     ('scan_sessions', 'Scan Sessions')],
                            validators=[DataRequired()])
    
    port = IntegerField('Port Number', validators=[Optional(), NumberRange(min=1, max=65535)])
    
    software = StringField('Software Name (partial match)', validators=[Optional(), Length(max=100)])
    
    submit = SubmitField('Run Query')

class CustomQueryForm(FlaskForm):
    sql_query = TextAreaField('SQL Query', validators=[DataRequired()])
    save_query = BooleanField('Save Query')
    query_name = StringField('Query Name', validators=[Optional(), Length(max=100)])
    submit = SubmitField('Run Query')
