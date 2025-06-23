import os
import sys
import logging
from datetime import datetime, date, timedelta
from flask import Flask, session, redirect, url_for, flash, render_template, request, Response, jsonify
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required
from flask_mailman import Mail
from werkzeug.security import generate_password_hash
import jinja2
from flask_wtf import CSRFProtect
from utils import trans_function as trans, is_valid_email
from flask_session import Session
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer
from flask_babel import Babel
from functools import wraps

# Debug dnspython import
try:
    import dns
    print("dnspython is importable")
except ImportError:
    raise RuntimeError("dnspython is not installed or not importable")

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app initialization
app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)
CSRFProtect(app)

# Environment configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY']:
    logger.error("SECRET_KEY environment variable is not set")
    raise ValueError("SECRET_KEY must be set in environment variables")

app.config['MONGO_URI'] = os.getenv('MONGO_URI')
if not app.config['MONGO_URI']:
    logger.error("MONGO_URI environment variable is not set")
    raise ValueError("MONGO_URI must be set in environment variables")

# MongoDB connection management
def get_mongo_db():
    """Get MongoDB database instance, ensuring fork-safe connection."""
    if not hasattr(app, 'mongo_client'):
        try:
            app.mongo_client = MongoClient(app.config['MONGO_URI'], serverSelectionTimeoutMS=5000)
            app.mongo_client.admin.command('ping')
            logger.info("MongoDB connection established")
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise RuntimeError(f"Cannot connect to MongoDB: {str(e)}")
    return app.mongo_client['ficore_accounting']

def close_mongo_db(exception=None):
    """Close MongoDB client connection."""
    if hasattr(app, 'mongo_client') and app.mongo_client:
        app.mongo_client.close()
        del app.mongo_client
        logger.info("MongoDB connection closed")

# Session configuration
app.config['SESSION_TYPE'] = 'mongodb'
app.config['SESSION_MONGODB_DB'] = 'ficore_accounting'
app.config['SESSION_MONGODB_COLLECTION'] = 'sessions'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV', 'development') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_NAME'] = 'ficore_session'

def init_session_mongo():
    """Initialize MongoDB session client post-fork."""
    if not hasattr(app, 'session_mongo_client'):
        mongo_uri = os.getenv('MONGO_URI')
        if not mongo_uri:
            logger.error("MONGO_URI environment variable not set. Session won't work correctly.")
            raise ValueError("MONGO_URI environment variable is required for MongoDB sessions.")
        app.session_mongo_client = MongoClient(mongo_uri)
        app.config['SESSION_MONGODB'] = app.session_mongo_client
    return app.session_mongo_client

# Initialize extensions
mail = Mail(app)
sess = Session()
sess.init_app(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per day", "100 per hour"],
    storage_uri=app.config['MONGO_URI'],
    storage_options={}
)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
babel = Babel(app)

# Register teardown handler
app.teardown_appcontext(close_mongo_db)

# Localization configuration
def get_locale():
    return session.get('lang', request.accept_languages.best_match(['en', 'ha'], default='en'))

babel.locale_selector = get_locale

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'users.login'

# Role-based access control decorator
from utils import requires_role, check_coin_balance

class User(UserMixin):
    def __init__(self, id, email, display_name=None, role='personal'):
        self.id = id
        self.email = email
        self.display_name = display_name or id
        self.role = role

    def get(self, key, default=None):
        user = get_mongo_db().users.find_one({'_id': self.id})
        return user.get(key, default) if user else default

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = get_mongo_db().users.find_one({'_id': user_id})
        if user_data:
            return User(user_data['_id'], user_data['email'], user_data.get('display_name'), user_data.get('role', 'personal'))
        return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {str(e)}")
        return None

# Register blueprints
from users.routes import users_bp
from coins.routes import coins_bp
from admin.routes import admin_bp
from settings.routes import settings_bp
from inventory.routes import inventory_bp
from reports.routes import reports_bp
from debtors.routes import debtors_bp
from creditors.routes import creditors_bp
from receipts.routes import receipts_bp
from payments.routes import payments_bp

app.register_blueprint(users_bp, url_prefix='/users')
app.register_blueprint(coins_bp, url_prefix='/coins')
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(settings_bp, url_prefix='/settings')
app.register_blueprint(inventory_bp, url_prefix='/inventory')
app.register_blueprint(reports_bp, url_prefix='/reports')
app.register_blueprint(debtors_bp, url_prefix='/debtors')
app.register_blueprint(creditors_bp, url_prefix='/creditors')
app.register_blueprint(receipts_bp, url_prefix='/receipts')
app.register_blueprint(payments_bp, url_prefix='/payments')

# Jinja2 globals and filters
with app.app_context():
    app.jinja_env.globals.update(
        FACEBOOK_URL=app.config.get('FACEBOOK_URL', 'https://www.facebook.com'),
        TWITTER_URL=app.config.get('TWITTER_URL', 'https://www.twitter.com'),
        LINKEDIN_URL=app.config.get('LINKEDIN_URL', 'https://www.linkedin.com'),
        trans=trans
    )

    @app.template_filter('trans')
    def trans_filter(key):
        return trans(key)

    @app.template_filter('format_number')
    def format_number(value):
        try:
            if isinstance(value, (int, float)):
                return f"{float(value):,.2f}"
            return str(value)
        except (ValueError, TypeError) as e:
            logger.warning(f"Error formatting number {value}: {str(e)}")
            return str(value)

    @app.template_filter('format_currency')
    def format_currency(value):
        try:
            value = float(value)
            locale = session.get('lang', 'en')
            symbol = '₦'
            if value.is_integer():
                return f"{symbol}{int(value):,}"
            return f"{symbol}{value:,.2f}"
        except (TypeError, ValueError) as e:
            logger.warning(f"Error formatting currency {value}: {str(e)}")
            return str(value)

    @app.template_filter('format_datetime')
    def format_datetime(value):
        try:
            locale = session.get('lang', 'en')
            format_str = '%B %d, %Y, %I:%M %p' if locale == 'en' else '%d %B %Y, %I:%M %p'
            if isinstance(value, datetime):
                return value.strftime(format_str)
            elif isinstance(value, date):
                return value.strftime('%B %d, %Y' if locale == 'en' else '%d %B %Y')
            elif isinstance(value, str):
                parsed = datetime.strptime(value, '%Y-%m-%d')
                return parsed.strftime(format_str)
            return str(value)
        except Exception as e:
            logger.warning(f"Error formatting datetime {value}: {str(e)}")
            return str(value)

    @app.template_filter('format_date')
    def format_date(value):
        try:
            locale = session.get('lang', 'en')
            format_str = '%Y-%m-%d' if locale == 'en' else '%d-%m-%Y'
            if isinstance(value, datetime):
                return value.strftime(format_str)
            elif isinstance(value, date):
                return value.strftime(format_str)
            elif isinstance(value, str):
                parsed = datetime.strptime(value, '%Y-%m-%d').date()
                return parsed.strftime(format_str)
            return str(value)
        except Exception as e:
            logger.warning(f"Error formatting date {value}: {str(e)}")
            return str(value)

@app.route('/api/translations/<lang>')
def get_translations(lang):
    valid_langs = ['en', 'ha']
    if lang in valid_langs:
        return jsonify({'translations': app.config.get('TRANSLATIONS', {}).get(lang, app.config.get('TRANSLATIONS', {}).get('en', {}))})
    return jsonify({'translations': app.config.get('TRANSLATIONS', {}).get('en', {})}), 400

@app.route('/setlang/<lang>')
def set_language(lang):
    valid_langs = ['en', 'ha']
    if lang in valid_langs:
        session['lang'] = lang
        if current_user.is_authenticated:
            get_mongo_db().users.update_one({'_id': current_user.id}, {'$set': {'language': lang}})
        flash(trans('language_updated', default='Language updated'), 'success')
    else:
        flash(trans('invalid_language', default='Invalid language'), 'danger')
    return redirect(request.referrer or url_for('index'))

@app.route('/contact')
def contact():
    return render_template('general/contact.html')

@app.route('/privacy')
def privacy():
    return render_template('general/privacy.html')

@app.route('/terms')
def terms():
    return render_template('general/terms.html')

@app.route('/set_dark_mode', methods=['POST'])
def set_dark_mode():
    data = request.get_json()
    dark_mode = str(data.get('dark_mode', False)).lower() == 'true'
    session['dark_mode'] = dark_mode
    if current_user.is_authenticated:
        get_mongo_db().users.update_one({'_id': current_user.id}, {'$set': {'dark_mode': dark_mode}})
    return Response(status=204)

def setup_database():
    try:
        db = get_mongo_db()
        collections = db.list_collection_names()
        db.command('ping')
        logger.info("MongoDB connection successful during setup")

        # Clean up guest data
        db.feedback.delete_many({'user_id': {'$in': ['guest', None]}})

        # Users collection
        if 'users' not in collections:
            db.create_collection('users', validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['_id', 'email', 'password', 'role', 'coin_balance', 'created_at'],
                    'properties': {
                        '_id': {'bsonType': 'string'},
                        'email': {'bsonType': 'string'},
                        'password': {'bsonType': 'string'},
                        'role': {'enum': ['personal', 'trader', 'agent', 'admin']},
                        'coin_balance': {'bsonType': 'int'},
                        'language': {'enum': ['en', 'ha']},
                        'created_at': {'bsonType': 'date'}
                    }
                }
            })
        users_indexes = db.users.index_information()
        if 'email_1' not in users_indexes:
            db.users.create_index([('email', ASCENDING)], unique=True)
        if 'reset_token_1' not in users_indexes:
            db.users.create_index([('reset_token', ASCENDING)], sparse=True)
        if 'role_1' not in users_indexes:
            db.users.create_index([('role', ASCENDING)])

        db.users.update_many(
            {'role': {'$exists': False}},
            {'$set': {'role': 'personal', 'coin_balance': 0, 'language': 'en'}}
        )

        # Coin transactions collection
        if 'coin_transactions' not in collections:
            db.create_collection('coin_transactions', validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['user_id', 'amount', 'type', 'date'],
                    'properties': {
                        'user_id': {'bsonType': 'string'},
                        'amount': {'bsonType': 'int'},
                        'type': {'enum': ['purchase', 'spend', 'credit', 'admin_credit']},
                        'date': {'bsonType': 'date'},
                        'ref': {'bsonType': 'string'}
                    }
                }
            })
        db.coin_transactions.create_index([('user_id', ASCENDING)])
        db.coin_transactions.create_index([('date', DESCENDING)])

        # Audit logs collection
        if 'audit_logs' not in collections:
            db.create_collection('audit_logs', validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['admin_id', 'action', 'details', 'timestamp'],
                    'properties': {
                        'admin_id': {'bsonType': 'string'},
                        'action': {'bsonType': 'string'},
                        'details': {'bsonType': 'object'},
                        'timestamp': {'bsonType': 'date'}
                    }
                }
            })
        db.audit_logs.create_index([('timestamp', DESCENDING)])

        # Debtors collection
        if 'debtors' not in collections:
            db.create_collection('debtors', validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['user_id', 'name', 'amount_owed', 'created_at'],
                    'properties': {
                        'user_id': {'bsonType': 'string'},
                        'name': {'bsonType': 'string'},
                        'amount_owed': {'bsonType': 'double'},
                        'created_at': {'bsonType': 'date'},
                        'contact': {'bsonType': 'string'}
                    }
                }
            })
        db.debtors.create_index([('user_id', ASCENDING)])
        db.debtors.create_index([('created_at', DESCENDING)])

        # Creditors collection
        if 'creditors' not in collections:
            db.create_collection('creditors', validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['user_id', 'name', 'amount_owed', 'created_at'],
                    'properties': {
                        'user_id': {'bsonType': 'string'},
                        'name': {'bsonType': 'string'},
                        'amount_owed': {'bsonType': 'double'},
                        'created_at': {'bsonType': 'date'},
                        'contact': {'bsonType': 'string'}
                    }
                }
            })
        db.creditors.create_index([('user_id', ASCENDING)])
        db.creditors.create_index([('created_at', DESCENDING)])

        # Receipts collection
        if 'receipts' not in collections:
            db.create_collection('receipts', validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['user_id', 'file_id', 'upload_date'],
                    'properties': {
                        'user_id': {'bsonType': 'string'},
                        'file_id': {'bsonType': 'objectId'},
                        'upload_date': {'bsonType': 'date'},
                        'filename': {'bsonType': 'string'}
                    }
                }
            })
        db.receipts.create_index([('user_id', ASCENDING)])
        db.receipts.create_index([('upload_date', DESCENDING)])

        # Payments collection
        if 'payments' not in collections:
            db.create_collection('payments', validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['user_id', 'amount', 'recipient', 'created_at'],
                    'properties': {
                        'user_id': {'bsonType': 'string'},
                        'amount': {'bsonType': 'double'},
                        'recipient': {'bsonType': 'string'},
                        'created_at': {'bsonType': 'date'},
                        'method': {'enum': ['card', 'bank', 'cash']}
                    }
                }
            })
        db.payments.create_index([('user_id', ASCENDING)])
        db.payments.create_index([('created_at', DESCENDING)])

        # Inventory collection
        if 'inventory' not in collections:
            db.create_collection('inventory', validator={
                '$jsonSchema': {
                    'bsonType': 'object',
                    'required': ['user_id', 'item_name', 'qty', 'created_at'],
                    'properties': {
                        'user_id': {'bsonType': 'string'},
                        'item_name': {'bsonType': 'string'},
                        'qty': {'bsonType': 'int'},
                        'created_at': {'bsonType': 'date'},
                        'unit': {'bsonType': 'string'},
                        'buying_price': {'bsonType': 'double'},
                        'selling_price': {'bsonType': 'double'},
                        'threshold': {'bsonType': 'int'}
                    }
                }
            })
        db.inventory.create_index([('user_id', ASCENDING)])
        db.inventory.create_index([('created_at', DESCENDING)])

        # Feedback collection
        if 'feedback' not in collections:
            db.create_collection('feedback')
            db.feedback.create_index([('user_id', ASCENDING)], sparse=True)
            db.feedback.create_index([('timestamp', DESCENDING)])

        # Sessions collection with TTL index
        if 'sessions' not in collections:
            db.create_collection('sessions')
        # Ensure TTL index for session cleanup
        db.sessions.create_index([('expires', ASCENDING)], expireAfterSeconds=0, name='session_expiry_index')

        # Admin user creation
        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_email = os.getenv('ADMIN_EMAIL', 'ficorerecords@gmail.com')
        admin_password = os.getenv('ADMIN_PASSWORD', 'Admin123!')
        if not db.users.find_one({'_id': admin_username}):
            db.users.insert_one({
                '_id': admin_username.lower(),
                'email': admin_email.lower(),
                'password': generate_password_hash(admin_password),
                'role': 'admin',
                'coin_balance': 0,
                'language': 'en',
                'dark_mode': False,
                'is_admin': True,
                'setup_complete': True,
                'display_name': admin_username,
                'created_at': datetime.utcnow()
            })
            logger.info(f"Default admin user created: {admin_username}")

        logger.info("Database setup completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return False

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com;"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.route('/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')

@app.route('/manifest.json')
def manifest():
    return {
        'name': 'FiCore',
        'short_name': 'FiCore',
        'description': 'Manage your finances with ease',
        'theme_color': '#007bff',
        'background_color': '#ffffff',
        'display': 'standalone',
        'scope': '/',
        'start_url': '/',
        'icons': [
            {'src': '/static/icons/icon-192x192.png', 'sizes': '192x192', 'type': 'image/png'},
            {'src': '/static/icons/icon-512x512.png', 'sizes': '512x512', 'type': 'image/png'}
        ]
    }

# Routes
@app.route('/')
def index():
    return render_template('general/home.html')

@app.route('/about')
def about():
    return render_template('general/about.html')

@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    lang = session.get('lang', 'en')
    tool_options = [
        ['profile', trans('tool_profile', default='Profile')],
        ['coins', trans('tool_coins', default='Coins')],
        ['debtors', trans('debtors', default='Debtors')],
        ['creditors', trans('creditors', default='Creditors')],
        ['receipts', trans('receipts', default='Receipts')],
        ['payments', trans('payments', default='Payments')],
        ['inventory', trans('inventory', default='Inventory')],
        ['reports', trans('reports', default='Reports')]
    ]
    if request.method == 'POST':
        try:
            if not check_coin_balance(1):
                flash(trans('insufficient_coins', default='Insufficient coins to submit feedback'), 'danger')
                return redirect(url_for('coins.purchase'))
            tool_name = request.form.get('tool_name')
            rating = request.form.get('rating')
            comment = request.form.get('comment', '').strip()
            valid_tools = [option[0] for option in tool_options]
            if not tool_name or tool_name not in valid_tools:
                flash(trans('invalid_tool', default='Please select a valid tool'), 'danger')
                return render_template('general/feedback.html', tool_options=tool_options)
            if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
                flash(trans('invalid_rating', default='Rating must be between 1 and 5'), 'danger')
                return render_template('general/feedback.html', tool_options=tool_options)
            db = get_mongo_db()
            db.users.update_one({'_id': current_user.id}, {'$inc': {'coin_balance': -1}})
            db.coin_transactions.insert_one({
                'user_id': current_user.id,
                'amount': -1,
                'type': 'spend',
                'ref': f"FEEDBACK_{datetime.utcnow().isoformat()}",
                'date': datetime.utcnow()
            })
            feedback_entry = {
                'user_id': current_user.id,
                'tool_name': tool_name,
                'rating': int(rating),
                'comment': comment or None,
                'timestamp': datetime.utcnow()
            }
            db.feedback.insert_one(feedback_entry)
            db.audit_logs.insert_one({
                'admin_id': 'system',
                'action': 'submit_feedback',
                'details': {'user_id': current_user.id, 'tool_name': tool_name},
                'timestamp': datetime.utcnow()
            })
            flash(trans('feedback_success', default='Feedback submitted successfully'), 'success')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Error processing feedback: {str(e)}")
            flash(trans('feedback_error', default='An error occurred while submitting feedback'), 'danger')
            return render_template('general/feedback.html', tool_options=tool_options), 500
    return render_template('general/feedback.html', tool_options=tool_options)

@app.route('/dashboard/admin')
@login_required
@requires_role('admin')
def admin_dashboard():
    try:
        db = get_mongo_db()
        inventory = list(db.inventory.find().sort('created_at', DESCENDING).limit(50))
        payments = list(db.payments.find().sort('created_at', DESCENDING).limit(50))
        receipts = list(db.receipts.find().sort('upload_date', DESCENDING).limit(50))
        coin_transactions = list(db.coin_transactions.find().sort('date', DESCENDING).limit(50))
        for item in inventory:
            item['_id'] = str(item['_id'])
        for payment in payments:
            payment['_id'] = str(payment['_id'])
        for receipt in receipts:
            receipt['_id'] = str(receipt['_id'])
        for coin_tx in coin_transactions:
            coin_tx['_id'] = str(coin_tx['_id'])
        return render_template('dashboard/admin_dashboard.html',
                              inventory=inventory,
                              payments=payments,
                              receipts=receipts,
                              coin_transactions=coin_transactions)
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred while loading the dashboard'), 'danger')
        return redirect(url_for('index')), 500

@app.route('/dashboard/general')
@login_required
def general_dashboard():
    try:
        db = get_mongo_db()
        user = db.users.find_one({'_id': current_user.id})
        query = {'user_id': current_user.id}
        if user.get('role') == 'admin':
            query = {}
        recent_inventory = list(db.inventory.find(query).sort('created_at', DESCENDING).limit(50))
        recent_payments = list(db.payments.find(query).sort('created_at', DESCENDING).limit(50))
        recent_receipts = list(db.receipts.find(query).sort('upload_date', DESCENDING).limit(50))
        recent_coin_txs = list(db.coin_transactions.find(query).sort('date', DESCENDING).limit(10))
        for item in recent_inventory:
            item['_id'] = str(item['_id'])
        for payment in recent_payments:
            payment['_id'] = str(payment['_id'])
        for receipt in recent_receipts:
            receipt['_id'] = str(receipt['_id'])
        for coin_tx in recent_coin_txs:
            coin_tx['_id'] = str(coin_tx['_id'])
        coin_balance = user.get('coin_balance', 0)
        return render_template('dashboard/general_dashboard.html',
                              recent_inventory=recent_inventory,
                              recent_payments=recent_payments,
                              recent_receipts=recent_receipts,
                              recent_coin_txs=recent_coin_txs,
                              coin_balance=coin_balance)
    except Exception as e:
        logger.error(f"Error fetching dashboard data: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred while loading the dashboard'), 'danger')
        return render_template('dashboard/general_dashboard.html',
                              recent_inventory=[],
                              recent_payments=[],
                              recent_receipts=[],
                              recent_coin_txs=[],
                              coin_balance=0), 500

@app.route('/setup', methods=['GET'])
@limiter.limit("10 per minute")
def setup_database_route():
    setup_key = request.args.get('key')
    if setup_key != os.getenv('SETUP_KEY', 'setup-secret'):
        return render_template('errors/403.html', content=trans('forbidden_access', default='Access denied')), 403
    if os.getenv('FLASK_ENV', 'development') == 'production' and not os.getenv('ALLOW_DB_SETUP', 'false').lower() == 'true':
        flash(trans('database_setup_disabled', default='Database setup disabled in production'), 'danger')
        return render_template('errors/403.html', content=trans('forbidden_access', default='Access denied')), 403
    if setup_database():
        flash(trans('database_setup_success', default='Database setup successful'), 'success')
        return redirect(url_for('index'))
    else:
        flash(trans('database_setup_error', default='An error occurred during database setup'), 'danger')
        return render_template('errors/500.html', content=trans('internal_error', default='Internal server error')), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html', message=trans('forbidden', default='Forbidden')), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html', message=trans('page_not_found', default='Page not found')), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html', message=trans('internal_server_error', default='Internal server error')), 500

# Gunicorn worker exit hook
def worker_exit(server, worker):
    """Close MongoDB connections on worker exit."""
    close_mongo_db()
    if hasattr(app, 'session_mongo_client'):
        app.session_mongo_client.close()
        logger.info("MongoDB session client closed on worker exit")

with app.app_context():
    init_session_mongo()
    if os.getenv('FLASK_ENV', 'development') != 'production' or os.getenv('ALLOW_DB_SETUP', 'false').lower() == 'true':
        if not setup_database():
            logger.error("Application startup aborted due to database initialization failure")
            raise RuntimeError("Database initialization failed")
    else:
        logger.info("Database initialization skipped in production environment")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting Flask app on port {port} at {datetime.now().strftime('%I:%M %p WAT on %B %d, %Y')}")
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV', 'development') == 'development')
