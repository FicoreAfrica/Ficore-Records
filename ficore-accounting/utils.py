import re
import logging
from datetime import datetime, date
from flask import flash, redirect, url_for, current_app, g, session
from flask_login import current_user
from functools import wraps
from translations import trans_function
from bson import ObjectId
from bson.errors import InvalidId
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from gridfs import GridFS

logger = logging.getLogger(__name__)

def get_user_query(user_id: str) -> dict:
    """Generate MongoDB query for user by ID, supporting both ObjectId and string."""
    try:
        # Try ObjectId first
        return {'_id': ObjectId(user_id)}
    except InvalidId:
        # Fall back to string
        logger.warning(f"User ID {user_id} is not a valid ObjectId, falling back to string query")
        return {'_id': user_id}

def is_admin():
    """Check if current user is an admin - TEMPORARY for testing.
    TODO: For production, replace with stricter check, e.g., user.get('is_admin', False).
    """
    return current_user.is_authenticated and current_user.role == 'admin'

def is_valid_email(email):
    """Validate email format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def requires_role(role):
    """Decorator to restrict access to a specific role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # TEMPORARY: Bypass role check for admin users during testing
            # TODO: Remove this bypass for production
            if is_admin():
                return f(*args, **kwargs)
            if not current_user.is_authenticated:
                flash(trans_function('login_required', default='Please log in to access this page'), 'danger')
                return redirect(url_for('users_blueprint.login'))
            if current_user.role != role:
                flash(trans_function('forbidden_access', default='Access denied'), 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_coin_balance(required_coins):
    """Check if user has sufficient coin balance."""
    # TEMPORARY: Bypass coin check for admin users during testing
    # TODO: Remove this bypass for production
    if is_admin():
        return True
    try:
        db = get_mongo_db()
        user_query = get_user_query(current_user.id)
        user = db.users.find_one(user_query)
        if not user:
            logger.error(f"User {current_user.id} not found")
            return False
        balance = user.get('coin_balance', 0)
        if balance < required_coins:
            logger.warning(f"Insufficient coins for user {current_user.id}: {balance} < {required_coins}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error checking coin balance for user {current_user.id}: {str(e)}")
        return False

def sanitize_input(value):
    """Sanitize input to prevent XSS and injection attacks."""
    if not isinstance(value, str):
        return value
    # Basic sanitization: strip tags and escape special characters
    return re.sub(r'<[^>]+>', '', value).strip()

def generate_invoice_number(user_id):
    """Generate unique invoice number based on user ID and timestamp."""
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    return f"INV-{user_id[:8]}-{timestamp}"

def format_currency(value):
    """Format a value as currency with appropriate symbol and locale."""
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

def format_date(value):
    """Format a date value based on locale."""
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

def get_mongo_db():
    """Get MongoDB database connection for the current request."""
    if 'db' not in g:
        try:
            # Initialize MongoClient once per app
            if 'mongo_client' not in current_app.extensions:
                mongo_uri = current_app.config['MONGO_URI']
                client = MongoClient(
                    mongo_uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=20000,
                    socketTimeoutMS=20000
                )
                client.admin.command('ping')  # Test connection
                current_app.extensions['mongo_client'] = client
                logger.info("MongoDB client initialized for application")
            g.mongo_client = current_app.extensions['mongo_client']
            db_name = current_app.config.get('SESSION_MONGODB_DB', 'ficore_accounting')
            g.db = g.mongo_client[db_name]
            g.gridfs = GridFS(g.db)
            current_app.extensions['pymongo'] = g.db
            current_app.extensions['gridfs'] = g.gridfs
            logger.debug(f"Using MongoClient: {g.mongo_client}")
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise RuntimeError(f"Cannot connect to MongoDB: {str(e)}")
        except Exception as e:
            logger.error(f"Error initializing MongoDB connection: {str(e)}")
            raise RuntimeError(f"MongoDB initialization failed: {str(e)}")
    return g.db

def close_mongo_db(error=None):
    """Close MongoDB connection after request."""
    client = g.pop('mongo_client', None)
    db = g.pop('db', None)
    gridfs = g.pop('gridfs', None)
    if client is not None:
        logger.debug("MongoDB connection context cleaned up")
