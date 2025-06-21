from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, get_mongo_db
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

receipts_bp = Blueprint('receipts', __name__, url_prefix='/receipts')

@receipts_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all receipts for the current user."""
    try:
        db = get_mongo_db()
        receipts = db.transactions.find({
            'user_id': str(current_user.id),
            'type': 'receipt'
        }).sort('date', -1)
        return render_template('receipts/index.html', receipts=receipts, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching receipts for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard.index'))

@receipts_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new receipt."""
    from app.forms import TransactionForm
    form = TransactionForm()
    if not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to add a receipt. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            transaction = {
                'user_id': str(current_user.id),
                'type': 'receipt',
                'party_name': form.party_name.data,
                'date': form.date.data,
                'amount': form.amount.data,
                'description': form.description.data,
                'category': form.category.data,
                'created_at': datetime.utcnow()
            }
            db.transactions.insert_one(transaction)
            db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$inc': {'coin_balance': -1}}
            )
            db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Receipt creation: {transaction['party_name']}"
            })
            flash(trans_function('add_receipt_success', default='Receipt added successfully'), 'success')
            return redirect(url_for('receipts.index'))
        except Exception as e:
            logger.error(f"Error adding receipt for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('receipts/add.html', form=form)

@receipts_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing receipt."""
    from app.forms import TransactionForm
    try:
        db = get_mongo_db()
        receipt = db.transactions.find_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id),
            'type': 'receipt'
        })
        if not receipt:
            flash(trans_function('transaction_not_found', default='Transaction not found'), 'danger')
            return redirect(url_for('receipts.index'))
        form = TransactionForm(data={
            'party_name': receipt['party_name'],
            'date': receipt['date'],
            'amount': receipt['amount'],
            'description': receipt['description'],
            'category': receipt['category']
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
                db.transactions.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_transaction}
                )
                flash(trans_function('edit_receipt_success', default='Receipt updated successfully'), 'success')
                return redirect(url_for('receipts.index'))
            except Exception as e:
                logger.error(f"Error updating receipt {id} for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('receipts/edit.html', form=form, receipt=receipt)
    except Exception as e:
        logger.error(f"Error fetching receipt {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('transaction_not_found', default='Transaction not found'), 'danger')
        return redirect(url_for('receipts.index'))

@receipts_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a receipt."""
    try:
        db = get_mongo_db()
        result = db.transactions.delete_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id),
            'type': 'receipt'
        })
        if result.deleted_count:
            flash(trans_function('delete_receipt_success', default='Receipt deleted successfully'), 'success')
        else:
            flash(trans_function('transaction_not_found', default='Transaction not found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting receipt {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return redirect(url_for('receipts.index'))
