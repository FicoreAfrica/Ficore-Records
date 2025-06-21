from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.utils import trans_function, requires_role, check_coin_balance, format_currency, format_date
from translations import trans_function
from app import mongo
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

payments_bp = Blueprint('payments', __name__, url_prefix='/payments')

@payments_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all payments for the current user."""
    try:
        payments = mongo.db.transactions.find({
            'user_id': str(current_user.id),
            'type': 'payment'
        }).sort('date', -1)
        return render_template('payments/index.html', payments=payments, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching payments for user {current_user.id}: {str(e)}")
        flash(trans('something_went_wrong'), 'danger')
        return redirect(url_for('dashboard.index'))

@payments_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new payment."""
    from app.forms import TransactionForm
    form = TransactionForm()
    if not check_coin_balance(1):
        flash(trans('insufficient_coins', default='Insufficient coins to add a payment. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    if form.validate_on_submit():
        try:
            transaction = {
                'user_id': str(current_user.id),
                'type': 'payment',
                'party_name': form.party_name.data,
                'date': form.date.data,
                'amount': form.amount.data,
                'description': form.description.data,
                'category': form.category.data,
                'created_at': datetime.utcnow()
            }
            mongo.db.transactions.insert_one(transaction)
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$inc': {'coin_balance': -1}}
            )
            mongo.db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Payment creation: {transaction['party_name']}"
            })
            flash(trans('add_payment_success', default='Payment added successfully'), 'success')
            return redirect(url_for('payments.index'))
        except Exception as e:
            logger.error(f"Error adding payment for user {current_user.id}: {str(e)}")
            flash(trans('something_went_wrong'), 'danger')
    return render_template('payments/add.html', form=form)

@payments_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing payment."""
    from app.forms import TransactionForm
    try:
        payment = mongo.db.transactions.find_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id),
            'type': 'payment'
        })
        if not payment:
            flash(trans('transaction_not_found'), 'danger')
            return redirect(url_for('payments.index'))
        form = TransactionForm(data={
            'party_name': payment['party_name'],
            'date': payment['date'],
            'amount': payment['amount'],
            'description': payment['description'],
            'category': payment['category']
        })
        if form.validate_on_submit():
            try:
                updated_transaction = {
                    'party_name': form.party_name.data,
                    'date': form.date.data,
                    'amount': form.amount.data,
                    'description': form.description.data,
                    'category': form.category.data,
                    'updated_at': datetime.utcnow()
                }
                mongo.db.transactions.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_transaction}
                )
                flash(trans('edit_payment_success', default='Payment updated successfully'), 'success')
                return redirect(url_for('payments.index'))
            except Exception as e:
                logger.error(f"Error updating payment {id} for user {current_user.id}: {str(e)}")
                flash(trans('something_went_wrong'), 'danger')
        return render_template('payments/edit.html', form=form, payment=payment)
    except Exception as e:
        logger.error(f"Error fetching payment {id} for user {current_user.id}: {str(e)}")
        flash(trans('transaction_not_found'), 'danger')
        return redirect(url_for('payments.index'))

@payments_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a payment."""
    try:
        result = mongo.db.transactions.delete_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id),
            'type': 'payment'
        })
        if result.deleted_count:
            flash(trans('delete_payment_success', default='Payment deleted successfully'), 'success')
        else:
            flash(trans('transaction_not_found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting payment {id} for user {current_user.id}: {str(e)}")
        flash(trans('something_went_wrong'), 'danger')
    return redirect(url_for('payments.index'))
