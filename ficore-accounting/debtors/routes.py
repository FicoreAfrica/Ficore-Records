from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date
from app import mongo
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

debtors_bp = Blueprint('debtors', __name__, url_prefix='/debtors')

@debtors_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all debtor invoices for the current user."""
    try:
        debtors = mongo.db.invoices.find({
            'user_id': str(current_user.id),
            'type': 'debtor'
        }).sort('created_at', -1)
        return render_template('debtors/index.html', debtors=debtors, format_currency=format_currency, format_date=format_date)
    except Exception as e:
        logger.error(f"Error fetching debtors for user {current_user.id}: {str(e)}")
        flash(trans('something_went_wrong'), 'danger')
        return redirect(url_for('dashboard.index'))

@debtors_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new debtor invoice."""
    from app.forms import InvoiceForm
    form = InvoiceForm()
    if not check_coin_balance(1):
        flash(trans('insufficient_coins', default='Insufficient coins to create a debtor. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    if form.validate_on_submit():
        try:
            invoice = {
                'user_id': str(current_user.id),
                'type': 'debtor',
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
                'ref': f"Debtor creation: {invoice['party_name']}"
            })
            flash(trans('create_debtor_success', default='Debtor created successfully'), 'success')
            return redirect(url_for('debtors.index'))
        except Exception as e:
            logger.error(f"Error creating debtor for user {current_user.id}: {str(e)}")
            flash(trans('something_went_wrong'), 'danger')
    return render_template('debtors/add.html', form=form)

@debtors_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing debtor invoice."""
    from app.forms import InvoiceForm
    try:
        debtor = mongo.db.invoices.find_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id),
            'type': 'debtor'
        })
        if not debtor:
            flash(trans('invoice_not_found'), 'danger')
            return redirect(url_for('debtors.index'))
        form = InvoiceForm(data={
            'party_name': debtor['party_name'],
            'phone': debtor['phone'],
            'due_date': debtor['due_date'],
            'items': debtor['items']
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
                flash(trans('edit_debtor_success', default='Debtor updated successfully'), 'success')
                return redirect(url_for('debtors.index'))
            except Exception as e:
                logger.error(f"Error updating debtor {id} for user {current_user.id}: {str(e)}")
                flash(trans('something_went_wrong'), 'danger')
        return render_template('debtors/edit.html', form=form, debtor=debtor)
    except Exception as e:
        logger.error(f"Error fetching debtor {id} for user {current_user.id}: {str(e)}")
        flash(trans('invoice_not_found'), 'danger')
        return redirect(url_for('debtors.index'))

@debtors_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete a debtor invoice."""
    try:
        result = mongo.db.invoices.delete_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id),
            'type': 'debtor'
        })
        if result.deleted_count:
            flash(trans('delete_debtor_success', default='Debtor deleted successfully'), 'success')
        else:
            flash(trans('invoice_not_found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting debtor {id} for user {current_user.id}: {str(e)}")
        flash(trans('something_went_wrong'), 'danger')
    return redirect(url_for('debtors.index'))
