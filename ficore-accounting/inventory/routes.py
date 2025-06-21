from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.utils import requires_role, check_coin_balance, format_currency, format_date
from app.translations import trans_function as trans
from app import mongo
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

inventory_bp = Blueprint('inventory', __name__, url_prefix='/inventory')

@inventory_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """List all inventory items for the current user."""
    try:
        items = mongo.db.inventory.find({
            'user_id': str(current_user.id)
        }).sort('created_at', -1)
        return render_template('inventory/index.html', items=items, format_currency=format_currency)
    except Exception as e:
        logger.error(f"Error fetching inventory for user {current_user.id}: {str(e)}")
        flash(trans('something_went_wrong'), 'danger')
        return redirect(url_for('dashboard.index'))

@inventory_bp.route('/low_stock')
@login_required
@requires_role('trader')
def low_stock():
    """List inventory items with low stock."""
    try:
        low_stock_items = mongo.db.inventory.find({
            'user_id': str(current_user.id),
            'qty': {'$lte': mongo.db.inventory.threshold}
        }).sort('qty', 1)
        return render_template('inventory/low_stock.html', items=low_stock_items, format_currency=format_currency)
    except Exception as e:
        logger.error(f"Error fetching low stock items for user {current_user.id}: {str(e)}")
        flash(trans('something_went_wrong'), 'danger')
        return redirect(url_for('inventory.index'))

@inventory_bp.route('/add', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def add():
    """Add a new inventory item."""
    from app.forms import InventoryForm
    form = InventoryForm()
    if not check_coin_balance(1):
        flash(trans('insufficient_coins', default='Insufficient coins to add an item. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    if form.validate_on_submit():
        try:
            item = {
                'user_id': str(current_user.id),
                'item_name': form.item_name.data,
                'qty': form.qty.data,
                'unit': form.unit.data,
                'buying_price': form.buying_price.data,
                'selling_price': form.selling_price.data,
                'threshold': form.threshold.data,
                'created_at': datetime.utcnow()
            }
            mongo.db.inventory.insert_one(item)
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$inc': {'coin_balance': -1}}
            )
            mongo.db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Inventory item creation: {item['item_name']}"
            })
            flash(trans('add_item_success', default='Inventory item added successfully'), 'success')
            return redirect(url_for('inventory.index'))
        except Exception as e:
            logger.error(f"Error adding inventory item for user {current_user.id}: {str(e)}")
            flash(trans('something_went_wrong'), 'danger')
    return render_template('inventory/add.html', form=form)

@inventory_bp.route('/edit/<id>', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def edit(id):
    """Edit an existing inventory item."""
    from app.forms import InventoryForm
    try:
        item = mongo.db.inventory.find_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id)
        })
        if not item:
            flash(trans('item_not_found', default='Item not found'), 'danger')
            return redirect(url_for('inventory.index'))
        form = InventoryForm(data={
            'item_name': item['item_name'],
            'qty': item['qty'],
            'unit': item['unit'],
            'buying_price': item['buying_price'],
            'selling_price': item['selling_price'],
            'threshold': item['threshold']
        })
        if form.validate_on_submit():
            try:
                updated_item = {
                    'item_name': form.item_name.data,
                    'qty': form.qty.data,
                    'unit': form.unit.data,
                    'buying_price': form.buying_price.data,
                    'selling_price': form.selling_price.data,
                    'threshold': form.threshold.data,
                    'updated_at': datetime.utcnow()
                }
                mongo.db.inventory.update_one(
                    {'_id': ObjectId(id)},
                    {'$set': updated_item}
                )
                flash(trans('edit_item_success', default='Inventory item updated successfully'), 'success')
                return redirect(url_for('inventory.index'))
            except Exception as e:
                logger.error(f"Error updating inventory item {id} for user {current_user.id}: {str(e)}")
                flash(trans('something_went_wrong'), 'danger')
        return render_template('inventory/edit.html', form=form, item=item)
    except Exception as e:
        logger.error(f"Error fetching inventory item {id} for user {current_user.id}: {str(e)}")
        flash(trans('item_not_found'), 'danger')
        return redirect(url_for('inventory.index'))

@inventory_bp.route('/delete/<id>', methods=['POST'])
@login_required
@requires_role('trader')
def delete(id):
    """Delete an inventory item."""
    try:
        result = mongo.db.inventory.delete_one({
            '_id': ObjectId(id),
            'user_id': str(current_user.id)
        })
        if result.deleted_count:
            flash(trans('delete_item_success', default='Inventory item deleted successfully'), 'success')
        else:
            flash(trans('item_not_found'), 'danger')
    except Exception as e:
        logger.error(f"Error deleting inventory item {id} for user {current_user.id}: {str(e)}")
        flash(trans('something_went_wrong'), 'danger')
    return redirect(url_for('inventory.index'))