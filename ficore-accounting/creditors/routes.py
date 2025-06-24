from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, FloatField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional
import logging

logger = logging.getLogger(__name__)

class CreditorForm(FlaskForm):
    name = StringField('Creditor Name', validators=[DataRequired()])
    contact = StringField('Contact', validators=[Optional()])
    amount_owed = FloatField('Amount Owed', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    submit = SubmitField('Add Creditor')

creditors_bp = Blueprint('creditors', __name__, url_prefix='/creditors')

@creditors_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all creditor records for the current user."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to view all creditor records during testing
        # TODO: Restore original user_id filter for production
        query = {'type': 'creditor'} if is_admin() else {'user_id': str(current_user.id), 'type': 'creditor'}
        creditors = list(db.records.find(query).sort('created_at', -1))
        return render_template('creditors/index.html', creditors=creditors, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching creditors for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@creditors_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new creditor record."""
    form = CreditorForm()
    # TEMPORARY: Bypass coin check for admin during testing
    # TODO: Restore original check_coin_balance(1) for production
    if not is_admin() and not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to create a creditor. Purchase more coins.'), 'danger')
        return redirect(url_for('coins_blueprint.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            record = {
                'user_id': str(current_user.id),
                'type': 'creditor',
                'name': form.name.data,
                'contact': form.contact.data,
                'amount_owed': form.amount_owed.data,
                'description': form.description.data,
                'created_at': datetime.utcnow()
            }
            db.records.insert_one(record)
            # TEMPORARY: Skip coin deduction for admin during testing
            # TODO: Restore original coin deduction for production
            if not is_admin():
                user_query = get_user_query(str(current_user.id))
                db.users.update_one(
                    user_query,
                    {'$inc': {'coin_balance': -1}}
                )
                db.coin_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -1,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"Creditor creation: {record['name']}"
                })
            flash(trans_function('create_creditor_success', default='Creditor created successfully'), 'success')
            return redirect(url_for('creditors_blueprint.index'))
        except Exception as e:
            logger.error(f"Error creating creditor for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong'), 'danger')
    return render_template('creditors/add.html', form=form)

@creditors_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing creditor record."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to edit any creditor record during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'creditor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        if not creditor:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('creditors_blueprint.index'))
        form = CreditorForm(data={
            'name': creditor['name'],
            'contact': creditor['contact'],
            'amount_owed': creditor['amount_owed'],
            'description': creditor['description']
        })
        if form.validate_on_submit():
            try:
                updated_record = {
                    'name': form.name.data,
                    'contact': form.contact.data,
                    'amount_owed': form.amount_owed.data,
                    'description': form.description.data,
                    'updated_at': datetime.utcnow()
                }
                db.records.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_record}
                )
                flash(trans_function('edit_creditor_success', default='Creditor updated successfully'), 'success')
                return redirect(url_for('creditors_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating creditor {id} for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong'), 'danger')
        return render_template('creditors/edit.html', form=form, creditor=creditor)
    except Exception as e:
        logger.error(f"Error fetching creditor {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('creditors_blueprint.index'))

@creditors_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a creditor record."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to delete any creditor record during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'creditor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        result = db.records.delete_one(query)
        if result.deleted_count:
            flash(trans_function('delete_creditor_success', default='Creditor deleted successfully'), 'success')
        else:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting creditor {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong'), 'danger')
    return redirect(url_for('creditors_blueprint.index'))
