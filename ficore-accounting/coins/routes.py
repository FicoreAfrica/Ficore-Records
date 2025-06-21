from flask import Blueprint, request, render_template, redirect, url_for, flash, current_app, jsonify
from flask_wtf import FlaskForm
from wtforms import FloatField, StringField, SelectField, validators, SubmitField
from flask_wtf.file import FileField, FileAllowed
from flask_login import login_required, current_user
from datetime import datetime
from utils import trans_function, requires_role, check_coin_balance, get_mongo_db
from bson import ObjectId
from app import limiter
import logging
from gridfs import GridFS

logger = logging.getLogger(__name__)

coins_bp = Blueprint('coins', __name__, template_folder='templates/coins')

class PurchaseForm(FlaskForm):
    amount = SelectField(trans_function('coin_amount', default='Coin Amount'), choices=[
        ('10', '10 Coins'),
        ('50', '50 Coins'),
        ('100', '100 Coins')
    ], validators=[validators.DataRequired()])
    payment_method = SelectField(trans_function('payment_method', default='Payment Method'), choices=[
        ('card', trans_function('card', default='Credit/Debit Card')),
        ('bank', trans_function('bank', default='Bank Transfer'))
    ], validators=[validators.DataRequired()])
    submit = SubmitField(trans_function('purchase', default='Purchase'))

class ReceiptUploadForm(FlaskForm):
    receipt = FileField(trans_function('receipt', default='Receipt'), validators=[
        FileAllowed(['jpg', 'png', 'pdf'], trans_function('invalid_file_type', default='Only JPG, PNG, or PDF files are allowed'))
    ])
    submit = SubmitField(trans_function('upload_receipt', default='Upload Receipt'))

def credit_coins(user_id, amount, ref, type='purchase'):
    """Credit coins to a user and log transaction."""
    db = get_mongo_db()
    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$inc': {'coin_balance': amount}}
    )
    db.coin_transactions.insert_one({
        'user_id': user_id,
        'amount': amount,
        'type': type,
        'ref': ref,
        'date': datetime.utcnow()
    })
    # Log audit action
    try:
        db.audit_logs.insert_one({
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
            amount = int(form.amount.data)
            payment_method = form.payment_method.data
            payment_ref = f"PAY_{datetime.utcnow().isoformat()}"
            credit_coins(str(current_user.id), amount, payment_ref, 'purchase')
            flash(trans_function('purchase_success', default='Coins purchased successfully'), 'success')
            logger.info(f"User {current_user.id} purchased {amount} coins via {payment_method}")
            return redirect(url_for('coins.history'))
        except Exception as e:
            logger.error(f"Error purchasing coins for user {current_user.id}: {str(e)}")
            flash(trans_function('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('coins/purchase.html', form=form), 500
    return render_template('coins/purchase.html', form=form)

@coins_bp.route('/history', methods=['GET'])
@login_required
@limiter.limit("100 per hour")
def history():
    """View coin transaction history."""
    try:
        db = get_mongo_db()
        user = db.users.find_one({'_id': ObjectId(current_user.id)})
        query = {'user_id': str(current_user.id)}
        if user.get('role') == 'admin':
            query.pop('user_id')
        transactions = list(db.coin_transactions.find(query).sort('date', -1).limit(50))
        for tx in transactions:
            tx['_id'] = str(tx['_id'])
        return render_template('coins/history.html', transactions=transactions, coin_balance=user.get('coin_balance', 0))
    except Exception as e:
        logger.error(f"Error fetching coin history for user {current_user.id}: {str(e)}")
        flash(trans_function('core_something_went_wrong', default='An error occurred'), 'danger')
        return render_template('coins/history.html', transactions=[], coin_balance=0), 500

@coins_bp.route('/receipt_upload', methods=['GET', 'POST'])
@login_required
@requires_role(['trader', 'personal'])
@limiter.limit("10 per hour")
def receipt_upload():
    """Upload payment receipt."""
    form = ReceiptUploadForm()
    if not check_coin_balance(1):
        flash(trans_function('insufficient_coins', default='Insufficient coins to upload receipt. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            fs = current_app.extensions['gridfs']
            receipt_file = form.receipt.data
            file_id = fs.put(receipt_file, filename=receipt_file.filename, user_id=str(current_user.id), upload_date=datetime.utcnow())
            db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$inc': {'coin_balance': -1}}
            )
            ref = f"RECEIPT_UPLOAD_{datetime.utcnow().isoformat()}"
            db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'ref': ref,
                'date': datetime.utcnow()
            })
            db.audit_logs.insert_one({
                'admin_id': 'system',
                'action': 'receipt_upload',
                'details': {'user_id': str(current_user.id), 'file_id': str(file_id), 'ref': ref},
                'timestamp': datetime.utcnow()
            })
            flash(trans_function('receipt_uploaded', default='Receipt uploaded successfully'), 'success')
            logger.info(f"User {current_user.id} uploaded receipt {file_id}")
            return redirect(url_for('coins.history'))
        except Exception as e:
            logger.error(f"Error uploading receipt for user {current_user.id}: {str(e)}")
            flash(trans_function('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('coins/receipt_upload.html', form=form), 500
    return render_template('coins/receipt_upload.html', form=form)

@coins_bp.route('/balance', methods=['GET'])
@login_required
@limiter.limit("100 per minute")
def get_balance():
    """API endpoint to fetch current coin balance."""
    try:
        db = get_mongo_db()
        user = db.users.find_one({'_id': ObjectId(current_user.id)})
        return jsonify({'coin_balance': user.get('coin_balance', 0)})
    except Exception as e:
        logger.error(f"Error fetching coin balance for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans_function('core_something_went_wrong', default='An error occurred')}), 500
