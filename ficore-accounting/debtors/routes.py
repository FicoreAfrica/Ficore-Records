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

class DebtorForm(FlaskForm):
    name = StringField('Debtor Name', validators=[DataRequired()])
    contact = StringField('Contact', validators=[Optional()])
    amount_owed = FloatField('Amount Owed', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    submit = SubmitField('Add Debtor')

debtors_bp = Blueprint('debtors', __name__, url_prefix='/debtors')

@debtors_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all debtor records for the current user."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to view all debtor records during testing
        # TODO: Restore original user_id filter for production
        query = {'type': 'debtor'} if is_admin() else {'user_id': str(current_user.id), 'type': 'debtor'}
        debtors = list(db.records.find(query).sort('created_at', -1))
        return render_template('debtors/index.html', debtors=debtors, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching debtors for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@debtors_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new debtor record."""
    form = DebtorForm()
    # TEMPORARY: Bypass coin check for admin during testing
    # TODO: Restore original check_coin_balance(1) for production
    if not is_admin() and not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to create a debtor. Purchase more coins.'), 'danger')
        return redirect(url_for('coins_blueprint.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            record = {
                'user_id': str(current_user.id),
                'type': 'debtor',
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
                    'ref': f"Debtor creation: {record['name']}"
                })
            flash(trans_function('create_debtor_success', default='Debtor created successfully'), 'success')
            return redirect(url_for('debtors_blueprint.index'))
        except Exception as e:
            logger.error(f"Error creating debtor for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('debtors/add.html', form=form)

@debtors_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing debtor record."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to edit any debtor record during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        debtor = db.records.find_one(query)
        if not debtor:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('debtors_blueprint.index'))
        form = DebtorForm(data={
            'name': debtor['name'],
            'contact': debtor['contact'],
            'amount_owed': debtor['amount_owed'],
            'description': debtor['description']
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
                flash(trans_function('edit_debtor_success', default='Debtor updated successfully'), 'success')
                return redirect(url_for('debtors_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating debtor {id} for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('debtors/edit.html', form=form, debtor=debtor)
    except Exception as e:
        logger.error(f"Error fetching debtor {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('record_not_found', default='Record not found'), 'danger')
        return redirect(url_for('debtors_blueprint.index'))

@debtors_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a debtor record."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to delete any debtor record during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'debtor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'debtor'}
        result = db.records.delete_one(query)
        if result.deleted_count:
            flash(trans_function('delete_debtor_success', default='Debtor deleted successfully'), 'success')
        else:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting debtor {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return redirect(url_for('debtors_blueprint.index'))
