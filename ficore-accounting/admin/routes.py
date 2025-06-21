from flask import Blueprint, render_template, redirect, url_for, flash, current_app, request
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, validators, SubmitField
from datetime import datetime
from app.utils import trans_function as trans, requires_role
from bson import ObjectId
from app import limiter
import logging

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, template_folder='templates/admin')

class CreditForm(FlaskForm):
    username = StringField(trans('username', default='Username'), [
        validators.DataRequired(),
        validators.Length(min=3, max=50)
    ])
    amount = FloatField(trans('coin_amount', default='Coin Amount'), [
        validators.DataRequired(),
        validators.NumberRange(min=1)
    ])
    submit = SubmitField(trans('credit_coins', default='Credit Coins'))

def log_audit_action(action, details):
    """Log an admin action to audit_logs collection."""
    try:
        mongo = current_app.extensions['pymongo']
        mongo.db.audit_logs.insert_one({
            'admin_id': str(current_user.id),
            'action': action,
            'details': details,
            'timestamp': datetime.utcnow()
        })
    except Exception as e:
        logger.error(f"Error logging audit action: {str(e)}")

@admin_bp.route('/dashboard', methods=['GET'])
@login_required
@requires_role('admin')
@limiter.limit("100 per hour")
def dashboard():
    """Admin dashboard with system stats."""
    try:
        mongo = current_app.extensions['pymongo']
        user_count = mongo.db.users.count_documents({'role': {'$ne': 'admin'}})
        invoice_count = mongo.db.invoices.count_documents({})
        transaction_count = mongo.db.transactions.count_documents({})
        inventory_count = mongo.db.inventory.count_documents({})
        coin_tx_count = mongo.db.coin_transactions.count_documents({})
        audit_log_count = mongo.db.audit_logs.count_documents({})
        recent_users = list(mongo.db.users.find({'role': {'$ne': 'admin'}}).sort('created_at', -1).limit(10))
        for user in recent_users:
            user['_id'] = str(user['_id'])
        return render_template(
            'admin/dashboard.html',
            stats={
                'users': user_count,
                'invoices': invoice_count,
                'transactions': transaction_count,
                'inventory': inventory_count,
                'coin_transactions': coin_tx_count,
                'audit_logs': audit_log_count
            },
            recent_users=recent_users
        )
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
        return render_template('admin/dashboard.html', stats={}, recent_users=[]), 500

@admin_bp.route('/users', methods=['GET'])
@login_required
@requires_role('admin')
@limiter.limit("50 per hour")
def manage_users():
    """View and manage users."""
    try:
        mongo = current_app.extensions['pymongo']
        users = list(mongo.db.users.find({'role': {'$ne': 'admin'}}).sort('created_at', -1))
        for user in users:
            user['_id'] = str(user['_id'])
        return render_template('admin/users.html', users=users)
    except Exception as e:
        logger.error(f"Error fetching users for admin: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
        return render_template('admin/users.html', users=[]), 500

@admin_bp.route('/users/suspend/<user_id>', methods=['POST'])
@login_required
@requires_role('admin')
@limiter.limit("10 per hour")
def suspend_user(user_id):
    """Suspend a user account."""
    try:
        mongo = current_app.extensions['pymongo']
        result = mongo.db.users.update_one(
            {'_id': ObjectId(user_id), 'role': {'$ne': 'admin'}},
            {'$set': {'suspended': True, 'updated_at': datetime.utcnow()}}
        )
        if result.modified_count == 0:
            flash(trans('user_not_found', default='User not found'), 'danger')
        else:
            flash(trans('user_suspended', default='User suspended successfully'), 'success')
            logger.info(f"Admin {current_user.id} suspended user {user_id}")
            log_audit_action('suspend_user', {'user_id': user_id})
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Error suspending user {user_id}: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('admin.manage_users')), 500

@admin_bp.route('/users/delete/<user_id>', methods=['POST'])
@login_required
@requires_role('admin')
@limiter.limit("5 per hour")
def delete_user(user_id):
    """Delete a user and their data."""
    try:
        mongo = current_app.extensions['pymongo']
        mongo.db.invoices.delete_many({'user_id': user_id})
        mongo.db.transactions.delete_many({'user_id': user_id})
        mongo.db.inventory.delete_many({'user_id': user_id})
        mongo.db.coin_transactions.delete_many({'user_id': user_id})
        mongo.db.audit_logs.delete_many({'details.user_id': user_id})
        result = mongo.db.users.delete_one({'_id': ObjectId(user_id), 'role': {'$ne': 'admin'}})
        if result.deleted_count == 0:
            flash(trans('user_not_found', default='User not found'), 'danger')
        else:
            flash(trans('user_deleted', default='User deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted user {user_id}")
            log_audit_action('delete_user', {'user_id': user_id})
        return redirect(url_for('admin.manage_users'))
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('admin.manage_users')), 500

@admin_bp.route('/data/delete/<collection>/<item_id>', methods=['POST'])
@login_required
@requires_role('admin')
@limiter.limit("10 per hour")
def delete_item(collection, item_id):
    """Delete an item from a collection."""
    valid_collections = ['invoices', 'transactions', 'inventory']
    if collection not in valid_collections:
        flash(trans('invalid_collection', default='Invalid collection'), 'danger')
        return redirect(url_for('admin.dashboard'))
    try:
        mongo = current_app.extensions['pymongo']
        result = mongo.db[collection].delete_one({'_id': ObjectId(item_id)})
        if result.deleted_count == 0:
            flash(trans('item_not_found', default='Item not found'), 'danger')
        else:
            flash(trans('item_deleted', default='Item deleted successfully'), 'success')
            logger.info(f"Admin {current_user.id} deleted {collection} item {item_id}")
            log_audit_action(f'delete_{collection}_item', {'item_id': item_id, 'collection': collection})
        return redirect(url_for('admin.dashboard'))
    except Exception as e:
        logger.error(f"Error deleting {collection} item {item_id}: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('admin.dashboard')), 500

@admin_bp.route('/coins/credit', methods=['GET', 'POST'])
@login_required
@requires_role('admin')
@limiter.limit("10 per hour")
def credit_coins():
    """Manually credit coins to a user."""
    form = CreditForm()
    if form.validate_on_submit():
        try:
            mongo = current_app.extensions['pymongo']
            username = form.username.data.strip().lower()
            amount = int(form.amount.data)
            user = mongo.db.users.find_one({'username': username})
            if not user:
                flash(trans('user_not_found', default='User not found'), 'danger')
                return render_template('admin/coins_credit.html', form=form)
            mongo.db.users.update_one(
                {'_id': user['_id']},
                {'$inc': {'coin_balance': amount}}
            )
            ref = f"ADMIN_CREDIT_{datetime.utcnow().isoformat()}"
            mongo.db.coin_transactions.insert_one({
                'user_id': str(user['_id']),
                'amount': amount,
                'type': 'admin_credit',
                'ref': ref,
                'date': datetime.utcnow()
            })
            flash(trans('credit_success', default='Coins credited successfully'), 'success')
            logger.info(f"Admin {current_user.id} credited {amount} coins to user {username}")
            log_audit_action('credit_coins', {'user_id': str(user['_id']), 'amount': amount, 'ref': ref})
            return redirect(url_for('admin.dashboard'))
        except Exception as e:
            logger.error(f"Error crediting coins by admin {current_user.id}: {str(e)}")
            flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('admin/coins_credit.html', form=form), 500
    return render_template('admin/coins_credit.html', form=form)

@admin_bp.route('/audit', methods=['GET'])
@login_required
@requires_role('admin')
@limiter.limit("50 per hour")
def audit():
    """View audit logs of admin actions."""
    try:
        mongo = current_app.extensions['pymongo']
        logs = list(mongo.db.audit_logs.find().sort('timestamp', -1).limit(100))
        for log in logs:
            log['_id'] = str(log['_id'])
        return render_template('admin/audit.html', logs=logs)
    except Exception as e:
        logger.error(f"Error fetching audit logs for admin {current_user.id}: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
        return render_template('admin/audit.html', logs=[]), 500