from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, FloatField, SelectField, SubmitField
from wtforms.validators import DataRequired, Optional
import logging

logger = logging.getLogger(__name__)

class PaymentForm(FlaskForm):
    party_name = StringField('Recipient Name', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[DataRequired()])
    method = SelectField('Payment Method', choices=[
        ('cash', 'Cash'),
        ('card', 'Card'),
        ('bank', 'Bank Transfer')
    ], validators=[Optional()])
    category = StringField('Category', validators=[Optional()])
    submit = SubmitField('Add Payment')

payments_bp = Blueprint('payments', __name__, url_prefix='/payments')

@payments_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all payment cashflows for the current user."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to view all payment cashflows during testing
        # TODO: Restore original user_id filter for production
        query = {'type': 'payment'} if is_admin() else {'user_id': str(current_user.id), 'type': 'payment'}
        payments = list(db.cashflows.find(query).sort('created_at', -1))
        return render_template('payments/index.html', payments=payments, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching payments for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@payments_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new payment cashflow."""
    form = PaymentForm()
    # TEMPORARY: Bypass coin check for admin during testing
    # TODO: Restore original check_coin_balance(1) for production
    if not is_admin() and not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to add a payment. Purchase more coins.'), 'danger')
        return redirect(url_for('coins_blueprint.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            cashflow = {
                'user_id': str(current_user.id),
                'type': 'payment',
                'party_name': form.party_name.data,
                'amount': form.amount.data,
                'method': form.method.data,
                'category': form.category.data,
                'created_at': form.date.data,
                'updated_at': datetime.utcnow()
            }
            db.cashflows.insert_one(cashflow)
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
                    'ref': f"Payment creation: {cashflow['party_name']}"
                })
            flash(trans_function('add_payment_success', default='Payment added successfully'), 'success')
            return redirect(url_for('payments_blueprint.index'))
        except Exception as e:
            logger.error(f"Error adding payment for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('payments/add.html', form=form)

@payments_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing payment cashflow."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to edit any payment cashflow during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'payment'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'payment'}
        payment = db.cashflows.find_one(query)
        if not payment:
            flash(trans_function('cashflow_not_found', default='Cashflow not found'), 'danger')
            return redirect(url_for('payments_blueprint.index'))
        form = PaymentForm(data={
            'party_name': payment['party_name'],
            'date': payment['created_at'],
            'amount': payment['amount'],
            'method': payment.get('method'),
            'category': payment.get('category')
        })
        if form.validate_on_submit():
            try:
                updated_cashflow = {
                    'party_name': form.party_name.data,
                    'amount': form.amount.data,
                    'method': form.method.data,
                    'category': form.category.data,
                    'created_at': form.date.data,
                    'updated_at': datetime.utcnow()
                }
                db.cashflows.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_cashflow}
                )
                flash(trans_function('edit_payment_success', default='Payment updated successfully'), 'success')
                return redirect(url_for('payments_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating payment {id} for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('payments/edit.html', form=form, payment=payment)
    except Exception as e:
        logger.error(f"Error fetching payment {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('cashflow_not_found', default='Cashflow not found'), 'danger')
        return redirect(url_for('payments_blueprint.index'))

@payments_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a payment cashflow."""
    try:
        db = get_mongo_db()
        # TEMPORARY: Allow admin to delete any payment cashflow during testing
        # TODO: Restore original user_id filter for production
        query = {'_id': ObjectId(id), 'type': 'payment'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'payment'}
        result = db.cashflows.delete_one(query)
        if result.deleted_count:
            flash(trans_function('delete_payment_success', default='Payment deleted successfully'), 'success')
        else:
            flash(trans_function('cashflow_not_found', default='Cashflow not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting payment {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return redirect(url_for('payments_blueprint.index'))
