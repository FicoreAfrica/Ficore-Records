from flask import Blueprint, request, render_template, redirect, url_for, flash, current_app, jsonify
from flask_wtf import FlaskForm
from wtforms import FloatField, StringField, SelectField, validators, SubmitField
from flask_wtf.file import FileField, FileAllowed
from flask_login import login_required, current_user
from datetime import datetime
from utils import trans_function, requires_role, check_coin_balance
from bson import ObjectId
from app import limiter
import logging
from gridfs import GridFS

logger = logging.getLogger(__name__)

coins_bp = Blueprint('coins', __name__, template_folder='templates/coins')

class PurchaseForm(FlaskForm):
    amount = SelectField(trans('coin_amount', default='Coin Amount'), choices=[
        ('10', '10 Coins'),
        ('50', '50 Coins'),
        ('100', '100 Coins')
    ], validators=[validators.DataRequired()])
    payment_method = SelectField(trans('payment_method', default='Payment Method'), choices=[
        ('card', trans('card', default='Credit/Debit Card')),
        ('bank', trans('bank', default='Bank Transfer'))
    ], validators=[validators.DataRequired()])
    submit = SubmitField(trans('purchase', default='Purchase'))

class ReceiptUploadForm(FlaskForm):
    receipt = FileField(trans('receipt', default='Receipt'), validators=[
        FileAllowed(['jpg', 'png', 'pdf'], trans('invalid_file_type', default='Only JPG, PNG, or PDF files are allowed'))
    ])
    submit = SubmitField(trans('upload_receipt', default='Upload Receipt'))

def credit_coins(user_id, amount, ref, type='purchase'):
    """Credit coins to a user and log transaction."""
    mongo = current_app.extensions['pymongo']
    mongo.db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$inc': {'coin_balance': amount}}
    )
    mongo.db.coin_transactions.insert_one({
        'user_id': user_id,
        'amount': amount,
        'type': type,
        'ref': ref,
        'date': datetime.utcnow()
    })
    # Log audit action
    try:
        mongo.db.audit_logs.insert_one({
            'admin_id': 'system' if type == 'purchase' else str(current_user.id),
            'action': f'credit_coins_{type}',
            'details': {'user_id': user_id, 'amount': amount, 'ref': ref},
            'timestamp': datetime.utcnow()
        })
    except Exception as e:
        logger.error(f"Error logging audit action for coin credit: {str(e)}")

@coins_bp.route('/purchase', methods=['GET', 'POST'])
@login_required
@requires_role(['trader', 'personal'])
@limiter.limit("50 per hour")
def purchase():
    """Purchase coins."""
    form = PurchaseForm()
    if form.validate_on_submit():
        try:
            mongo = current_app.extensions['pymongo']
            amount = int(form.amount.data)
            payment_method = form.payment_method.data
            payment_ref = f"PAY_{datetime.utcnow().isoformat()}"
            credit_coins(str(current_user.id), amount, payment_ref, 'purchase')
            flash(trans('purchase_success', default='Coins purchased successfully'), 'success')
            logger.info(f"User {current_user.id} purchased {amount} coins via {payment_method}")
            return redirect(url_for('coins.history'))
        except Exception as e:
            logger.error(f"Error purchasing coins for user {current_user.id}: {str(e)}")
            flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('coins/purchase.html', form=form), 500
    return render_template('coins/purchase.html', form=form)

@coins_bp.route('/history', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def history():
    """View coin transaction history."""
    try:
        mongo = current_app.extensions['pymongo']
        user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
        query = {'user_id': str(current_user.id)}
        if user.get('role') == 'admin':
            query.pop('user_id')
        transactions = list(mongo.db.coin_transactions.find(query).sort('date', -1).limit(50))
        for tx in transactions:
            tx['_id'] = str(tx['_id'])
        return render_template('coins/history.html', transactions=transactions, coin_balance=user.get('coin_balance', 0))
    except Exception as e:
        logger.error(f"Error fetching coin history for user {current_user.id}: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
        return render_template('coins/history.html', transactions=[], coin_balance=0), 500

@coins_bp.route('/receipt_upload', methods=['GET', 'POST'])
@login_required
@requires_role(['trader', 'personal'])
@limiter.limit("10 per hour")
def receipt_upload():
    """Upload payment receipt."""
    form = ReceiptUploadForm()
    if not check_coin_balance(1):
        flash(trans('insufficient_coins', default='Insufficient coins to upload receipt. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    if form.validate_on_submit():
        try:
            mongo = current_app.extensions['pymongo']
            fs = GridFS(mongo.db)
            receipt_file = form.receipt.data
            file_id = fs.put(receipt_file, filename=receipt_file.filename, user_id=str(current_user.id), upload_date=datetime.utcnow())
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$inc': {'coin_balance': -1}}
            )
            ref = f"RECEIPT_UPLOAD_{datetime.utcnow().isoformat()}"
            mongo.db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'ref': ref,
                'date': datetime.utcnow()
            })
            mongo.db.audit_logs.insert_one({
                'admin_id': 'system',
                'action': 'receipt_upload',
                'details': {'user_id': str(current_user.id), 'file_id': str(file_id), 'ref': ref},
                'timestamp': datetime.utcnow()
            })
            flash(trans('receipt_uploaded', default='Receipt uploaded successfully'), 'success')
            logger.info(f"User {current_user.id} uploaded receipt {file_id}")
            return redirect(url_for('coins.history'))
        except Exception as e:
            logger.error(f"Error uploading receipt for user {current_user.id}: {str(e)}")
            flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('coins/receipt_upload.html', form=form), 500
    return render_template('coins/receipt_upload.html', form=form)

@coins_bp.route('/balance', methods=['GET'])
@login_required
@limiter.limit("100 per minute")
def get_balance():
    """API endpoint to fetch current coin balance."""
    try:
        mongo = current_app.extensions['pymongo']
        user = mongo.db.users.find_one({'_id': ObjectId(current_user.id)})
        return jsonify({'coin_balance': user.get('coin_balance', 0)})
    except Exception as e:
        logger.error(f"Error fetching coin balance for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans('core_something_went_wrong', default='An error occurred')}), 500
