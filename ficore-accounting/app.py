import os
import sys
import logging
from datetime import datetime, date, timedelta
from flask import Flask, session, redirect, url_for, flash, render_template, request, Response, jsonify, send_from_directory
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required
from werkzeug.security import generate_password_hash
import jinja2
from flask_wtf import CSRFProtect
from flask_wtf.csrf import validate_csrf, CSRFError
from utils import trans_function, trans_function as trans, is_valid_email, get_mongo_db, close_mongo_db, get_limiter, get_mail
from flask_session import Session
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from itsdangerous import URLSafeTimedSerializer
from flask_babel import Babel
from functools import wraps

# Ensure dnspython is installed for mongodb+srv:// URIs
try:
    import dns
    logging.info("dnspython is importable")
except ImportError:
    logging.error("dnspython is not installed. Required for mongodb+srv:// URIs. Install with: pip install pymongo[srv]")
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

# Validate MongoDB URI
if app.config['MONGO_URI'].startswith('mongodb+srv://') and 'dns' not in sys.modules:
    logger.error("Cannot use mongodb+srv:// URI without dnspython")
    raise ValueError("Invalid MongoDB URI: mongodb+srv:// requires dnspython")

# Session configuration
app.config['SESSION_TYPE'] = 'mongodb'
app.config['SESSION_MONGODB'] = None  # Will set to MongoClient instance below
app.config['SESSION_MONGODB_DB'] = 'ficore_accounting'
app.config['SESSION_MONGODB_COLLECT'] = 'sessions'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV', 'development') == 'production'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_NAME'] = 'ficore_session'

# Initialize MongoDB client at app startup
try:
    mongo_client = MongoClient(
        app.config['MONGO_URI'],
        connect=False,  # Defer connection for fork-safety
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=20000,
        socketTimeoutMS=20000
    )
    mongo_client.admin.command('ping')  # Test connection
    app.extensions['mongo_client'] = mongo_client
    app.config['SESSION_MONGODB'] = mongo_client  # Set MongoClient instance for Flask-Session
    logger.info("MongoDB client initialized at application startup")
except (ConnectionFailure, ServerSelectionTimeoutError) as e:
    logger.error(f"Failed to initialize MongoDB client: {str(e)}")
    raise RuntimeError(f"MongoDB initialization failed: {str(e)}")

# Initialize extensions
mail = get_mail(app)
sess = Session()
try:
    sess.init_app(app)
    logger.info("Flask-Session initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Flask-Session: {str(e)}")
    raise RuntimeError(f"Flask-Session initialization failed: {str(e)}")
limiter = get_limiter(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
babel = Babel(app)

# Flask-Babel 4.0.0 compatibility fix
def get_locale():
    return session.get('lang', request.accept_languages.best_match(['en', 'ha'], default='en'))
babel.locale_selector = get_locale

# Register teardown handler
app.teardown_appcontext(close_mongo_db)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'users_blueprint.login'

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
            logger.info(f"User loaded successfully: {user_id}")
            return User(user_data['_id'], user_data['email'], user_data.get('display_name'), user_data.get('role', 'personal'))
        logger.warning(f"User not found in database: {user_id}")
        return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {str(e)}")
        return None

# Register blueprints with unique names to avoid conflicts
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
from dashboard.routes import dashboard_bp

app.register_blueprint(users_bp, url_prefix='/users', name='users_blueprint')
app.register_blueprint(coins_bp, url_prefix='/coins', name='coins_blueprint')
app.register_blueprint(admin_bp, url_prefix='/admin', name='admin_blueprint')
app.register_blueprint(settings_bp, url_prefix='/settings', name='settings_blueprint')
app.register_blueprint(inventory_bp, url_prefix='/inventory', name='inventory_blueprint')
app.register_blueprint(reports_bp, url_prefix='/reports', name='reports_blueprint')
app.register_blueprint(debtors_bp, url_prefix='/debtors', name='debtors_blueprint')
app.register_blueprint(creditors_bp, url_prefix='/creditors', name='creditors_blueprint')
app.register_blueprint(receipts_bp, url_prefix='/receipts', name='receipts_blueprint')
app.register_blueprint(payments_bp, url_prefix='/payments', name='payments_blueprint')
app.register_blueprint(dashboard_bp, url_prefix='/dashboard', name='dashboard_blueprint')

# Jinja2 globals and filters
with app.app_context():
    app.jinja_env.globals.update(
        FACEBOOK_URL=app.config.get('FACEBOOK_URL', 'https://www.facebook.com'),
        TWITTER_URL=app.config.get('TWITTER_URL', 'https://www.twitter.com'),
        LINKEDIN_URL=app.config.get('LINKEDIN_URL', 'https://www.linkedin.com'),
        trans=trans,
        trans_function=trans_function
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
    try:
        validate_csrf(request.headers.get('X-CSRF-Token'))
        data = request.get_json()
        if not data or 'dark_mode' not in data:
            return jsonify({'status': 'error', 'message': 'Invalid request data'}), 400
        dark_mode = bool(data.get('dark_mode', False))
        session['dark_mode'] = dark_mode
        if current_user.is_authenticated:
            get_mongo_db().users.update_one({'_id': current_user.id}, {'$set': {'dark_mode': dark_mode}})
        return Response(status=204)
    except CSRFError:
        logger.error("CSRF validation failed for /set_dark_mode")
        return jsonify({'status': 'error', 'message': 'CSRF token invalid'}), 403
    except Exception as e:
        logger.error(f"Error in set_dark_mode: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')

def setup_database(force=False):
    try:
        db = get_mongo_db()
        collections = db.list_collection_names()
        db.command('ping')
        logger.info("MongoDB connection successful during setup")

        # Only drop collections if explicitly requested via initialize=True
        if initialize:
            for collection in collections:
                db.drop_collection(collection)
                logger.info(f"Dropped collection: {collection}")
        else:
            logger.info("Skipping collection drop to preserve data")

        # Define collections and their schemas
        collection_schemas = {
            'users': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['_id', 'email', 'password', 'role', 'coin_balance', 'created_at'],
                        'properties': {
                            '_id': {'bsonType': 'string'},
                            'email': {'bsonType': 'string', 'pattern': r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'},
                            'password': {'bsonType': 'string'},
                            'role': {'enum': ['personal', 'trader', 'agent', 'admin']},
                            'coin_balance': {'bsonType': 'int', 'minimum': 0},
                            'language': {'enum': ['en', 'ha']},
                            'created_at': {'bsonType': 'date'},
                            'display_name': {'bsonType': ['string', 'null']},
                            'dark_mode': {'bsonType': 'bool'},
                            'is_admin': {'bsonType': 'bool'},
                            'setup_complete': {'bsonType': 'bool'},
                            'reset_token': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    [('email', ASCENDING), {'unique': True}],
                    [('reset_token', ASCENDING), {'sparse': True}],
                    [('role', ASCENDING)]
                ]
            },
            'records': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'name', 'amount_owed', 'type', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'name': {'bsonType': 'string'},
                            'amount_owed': {'bsonType': 'double', 'minimum': 0},
                            'type': {'enum': ['debtor', 'creditor']},
                            'created_at': {'bsonType': 'date'},
                            'contact': {'bsonType': ['string', 'null']},
                            'description': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    [('user_id', ASCENDING), ('type', ASCENDING)],
                    [('created_at', DESCENDING)]
                ]
            },
            'cashflows': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'amount', 'party_name', 'type', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'amount': {'bsonType': 'double', 'minimum': 0},
                            'party_name': {'bsonType': 'string'},
                            'type': {'enum': ['payment', 'receipt']},
                            'created_at': {'bsonType': 'date'},
                            'method': {'enum': ['card', 'bank', 'cash', None]},
                            'category': {'bsonType': ['string', 'null']},
                            'file_id': {'bsonType': ['objectId', 'null']},
                            'filename': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    [('user_id', ASCENDING), ('type', ASCENDING)],
                    [('created_at', DESCENDING)]
                ]
            },
            'inventory': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'item_name', 'qty', 'created_at'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'item_name': {'bsonType': 'string'},
                            'qty': {'bsonType': 'int', 'minimum': 0},
                            'created_at': {'bsonType': 'date'},
                            'unit': {'bsonType': ['string', 'null']},
                            'buying_price': {'bsonType': ['double', 'null'], 'minimum': 0},
                            'selling_price': {'bsonType': ['double', 'null'], 'minimum': 0},
                            'threshold': {'bsonType': ['int', 'null'], 'minimum': 0},
                            'updated_at': {'bsonType': ['date', 'null']}
                        }
                    }
                },
                'indexes': [
                    [('user_id', ASCENDING)],
                    [('created_at', DESCENDING)]
                ]
            },
            'coin_transactions': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'amount', 'type', 'date'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'amount': {'bsonType': 'int'},
                            'type': {'enum': ['purchase', 'spend', 'credit', 'admin_credit']},
                            'date': {'bsonType': 'date'},
                            'ref': {'bsonType': ['string', 'null']}
                        }
                    }
                },
                'indexes': [
                    [('user_id', ASCENDING)],
                    [('date', DESCENDING)]
                ]
            },
            'audit_logs': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['admin_id', 'action', 'details', 'timestamp'],
                        'properties': {
                            'admin_id': {'bsonType': 'string'},
                            'action': {'bsonType': 'string'},
                            'details': {'bsonType': ['object', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    [('timestamp', DESCENDING)]
                ]
            },
            'feedback': {
                'validator': {
                    '$jsonSchema': {
                        'bsonType': 'object',
                        'required': ['user_id', 'tool_name', 'rating', 'timestamp'],
                        'properties': {
                            'user_id': {'bsonType': 'string'},
                            'tool_name': {'bsonType': 'string'},
                            'rating': {'bsonType': 'int', 'minimum': 1, 'maximum': 5},
                            'comment': {'bsonType': ['string', 'null']},
                            'timestamp': {'bsonType': 'date'}
                        }
                    }
                },
                'indexes': [
                    [('user_id', ASCENDING), {'sparse': True}],
                    [('timestamp', DESCENDING)]
                ]
            },
            'sessions': {
                'validator': {},
                'indexes': [
                    [('expiration', ASCENDING), {'expireAfterSeconds': 0, 'name': 'session_expiry_index'}]
                ]
            }
        }

        # Create collections and indexes only if they don't exist
        for collection_name, config in collection_schemas.items():
            if collection_name not in collections:
                db.create_collection(collection_name, validator=config.get('validator', {}))
                logger.info(f"Created collection: {collection_name}")
            for index in config.get('indexes', []):
                index_fields = index[0] if isinstance(index[0], list) else [index[0]]
                index_options = index[1] if len(index) > 1 else {}
                db[collection_name].create_index(index_fields, **index_options)
                logger.info(f"Created index on {collection_name}: {index_fields}")

        # Admin user creation
        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_email = os.getenv('ADMIN_EMAIL', 'ficore@gmail.com')
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
        'end_url': '/',
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
        ['debtors', trans('people', default='People')],
        ['creditors', trans('people')],
        ['receipts', trans('receipts', default='Receipts')],
        ['payment', trans('payment', default='Payments')],
        ['inventory', trans('inventory', default='Inventory')],
        ['report', trans('report', default='Reports')]
    ]
    if request.method == 'POST':
        try:
            if not check_coin_balance(1):
                flash(trans('insufficient_coins', default='Insufficient coins to submit feedback'), 'danger')
                return redirect(url_for('coins_blueprint.purchase'))
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
            from coins.routes import get_user_query
            query = get_user_query(str(current_user.id))
            result = db.users.update_one(query, {'$inc': {'coin_balance': -1}})
            if result.matched_count == 0:
                raise ValueError(f"No user found for ID {current_user.id}")
            db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'ref': f"FEEDBACK_{datetime.utcnow().isoformat()}",
                'date': datetime.utcnow()
            })
            feedback_entry = {
                'user_id': str(current_user.id),
                'tool_name': tool_name,
                'rating': int(rating),
                'comment': comment or None,
                'timestamp': datetime.utcnow()
            }
            db.feedback.insert_one(feedback_entry)
            db.audit_logs.insert_one({
                'admin_id': 'system',
                'action': 'submit_feedback',
                'details': {'user_id': str(current_user.id), 'tool_name': tool_name},
                'timestamp': datetime.utcnow()
            })
            flash(trans('feedback_success', default='Feedback submitted successfully'), 'success')
            return redirect(url_for('index'))
        except ValueError as e:
            logger.error(f"User not found: {str(e)}")
            flash(trans('user_not_found', default='User not found'), 'danger')
        except Exception as e:
            logger.error(f"Error processing feedback: {str(e)}")
            flash(trans('feedback_error', default='An error occurred while submitting feedback'), 'danger')
            return render_template('general/feedback.html', tool_options=tool_options), 500
    return render_template('general/feedback.html', tool_options=tool_options)

@app.route('/setup', methods=['GET'])
@limiter.limit("10 per minute")
def setup_database_route():
    setup_key = request.args.get('key')
    if setup_key != os.getenv('SETUP_KEY', 'setup-secret'):
        return render_template('errors/403.html', content=trans('forbidden_access', default='Access denied')), 403
    if setup_database(initialize=True):
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

# Gunicorn hooks
def worker_init():
    """Initialize MongoDB client for each Gunicorn worker."""
    with app.app_context():
        try:
            db = get_mongo_db()
            db.command('ping')
            logger.info("MongoDB connection successful for Gunicorn worker")
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(f"Failed to access MongoDB in worker_init: {str(e)}")
            raise RuntimeError(f"MongoDB access failed in worker_init: {str(e)}")

def worker_exit(server, worker):
    """Clean up request-specific MongoDB resources on worker exit."""
    close_mongo_db()
    logger.info("MongoDB request context cleaned up on worker exit")

with app.app_context():
    # Initialize database without dropping collections
    if not setup_database(initialize=False):
        logger.error("Application startup aborted due to database initialization failure")
        raise RuntimeError("Database initialization failed")

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting Flask app on port {port} at {datetime.now().strftime('%I:%M %p WAT on %B %d, %Y')}")
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_ENV', 'development') == 'development')
