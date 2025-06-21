from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date
from app import mongo
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

creditors_bp = Blueprint('creditors', __name__, url_prefix='/creditors')

@creditors_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all creditor invoices for the current user."""
    try:
        creditors = mongo.db.invoices.find({
            'user_id': str(current_user.id),
            'type': 'creditor'
        }).sort('created_at', -1)
        return render_template('creditors/index.html', creditors=creditors, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching creditors for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong'), 'danger')
        return redirect(url_for('dashboard.index'))

@creditors_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new creditor invoice."""
    from app.forms import InvoiceForm
    form = InvoiceForm()
    if not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to create a creditor. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    if form.validate_on_submit():
        try:
            invoice = {
                'user_id': str(current_user.id),
                'type': 'creditor',
                'party_name': form.party_name.data,
                'phone': form.phone.data,
                'items': [{
                    'description': item.description.data,
                    'quantity': item.quantity.data,
                    'price': item.price.data
                } for item in form.items],
                'total': sum(item.quantity.data * item.price.data for item in form.items),
                'paid_amount': 0,
                'due_date': form.due_date.data,
                'status': 'unpaid',
                'payments': [],
                'created_at': datetime.utcnow()
            }
            mongo.db.invoices.insert_one(invoice)
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$inc': {'coin_balance': -1}}
            )
            mongo.db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Creditor creation: {invoice['party_name']}"
            })
            flash(trans_function('create_creditor_success', default='Creditor created successfully'), 'success')
            return redirect(url_for('creditors.index'))
        except Exception as e:
            logger.error(f"Error creating creditor for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong'), 'danger')
    return render_template('creditors/add.html', form=form)

@creditors_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing creditor invoice."""
    from app.forms import InvoiceForm
    try:
        creditor = mongo.db.invoices.find_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id),
            'type': 'creditor'
        })
        if not creditor:
            flash(trans_function('invoice_not_found'), 'danger')
            return redirect(url_for('creditors.index'))
        form = InvoiceForm(data={
            'party_name': creditor['party_name'],
            'phone': creditor['phone'],
            'due_date': creditor['due_date'],
            'items': creditor['items']
        })
        if form.validate_on_submit():
            try:
                updated_invoice = {
                    'party_name': form.party_name.data,
                    'phone': form.phone.data,
                    'items': [{
                        'description': item.description.data,
                        'quantity': item.quantity.data,
                        'price': item.price.data
                    } for item in form.items],
                    'total': sum(item.quantity.data * item.price.data for item in form.items),
                    'due_date': form.due_date.data,
                    'updated_at': datetime.utcnow()
                }
                mongo.db.invoices.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_invoice}
                )
                flash(trans_function('edit_creditor_success', default='Creditor updated successfully'), 'success')
                return redirect(url_for('creditors.index'))
            except Exception as e:
                logger.error(f"Error updating creditor {id} for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong'), 'danger')
        return render_template('creditors/edit.html', form=form, creditor=creditor)
    except Exception as e:
        logger.error(f"Error fetching creditor {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('invoice_not_found'), 'danger')
        return redirect(url_for('creditors.index'))

@creditors_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a creditor invoice."""
    try:
        result = mongo.db.invoices.delete_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id),
            'type': 'creditor'
        })
        if result.deleted_count:
            flash(trans_function('delete_creditor_success', default='Creditor deleted successfully'), 'success')
        else:
            flash(trans_function('invoice_not_found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting creditor {id} for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong'), 'danger')
    return redirect(url_for('creditors.index'))
