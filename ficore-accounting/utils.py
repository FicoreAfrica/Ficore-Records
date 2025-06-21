import re
import logging
from datetime import datetime
from flask import flash, redirect, url_for, current_app
from flask_login import current_user
from functools import wraps
from translations import trans_function
from bson import ObjectId

logger = logging.getLogger(__name__)

def is_valid_email(email):
    """Validate email format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def format_currency(amount):
    """Format amount as currency with Naira symbol."""
    try:
        return f"₦{float(amount):,.2f}"
    except (ValueError, TypeError):
        logger.error(f"Invalid amount for currency formatting: {amount}")
        return "₦0.00"

def format_date(date):
    """Format date for display."""
    if isinstance(date, datetime):
        return date.strftime("%Y-%m-%d")
    return date

def format_datetime(date):
    """Format datetime for display."""
    if isinstance(date, datetime):
        return date.strftime("%Y-%m-%d %H:%M:%S")
    return date

def requires_role(role):
    """Decorator to restrict access to a specific role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash(trans_function('login_required', default='Please log in to access this page'), 'danger')
                return redirect(url_for('auth.login'))
            if current_user.role != role:
                flash(trans_function('forbidden_access', default='Access denied'), 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_coin_balance(required_coins):
    """Check if user has sufficient coin balance."""
    try:
        mongo = current_app.extensions['pymongo']
        user = mongo.db.users.find_one({'_id': current_user.id})
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
