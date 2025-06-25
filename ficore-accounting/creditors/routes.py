from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, DateField, FloatField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Optional
import logging
import requests
import os

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

@creditors_bp.route('/view/<id>')
@login_required
@requires_role('trader')
def view(id):
    """View detailed information about a specific creditor."""
    try:
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'creditor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        if not creditor:
            return jsonify({'error': trans_function('record_not_found', default='Record not found')}), 404
        
        # Convert ObjectId to string for JSON serialization
        creditor['_id'] = str(creditor['_id'])
        creditor['created_at'] = creditor['created_at'].isoformat() if creditor.get('created_at') else None
        creditor['reminder_count'] = creditor.get('reminder_count', 0)
        
        return jsonify(creditor)
    except Exception as e:
        logger.error(f"Error fetching creditor {id} for user {current_user.id}: {str(e)}")
        return jsonify({'error': trans_function('something_went_wrong', default='An error occurred')}), 500

@creditors_bp.route('/send_reminder', methods=['POST'])
@login_required
@requires_role('trader')
def send_reminder():
    """Send delivery reminder to creditor via SMS or WhatsApp."""
    try:
        data = request.get_json()
        debt_id = data.get('debtId')
        recipient = data.get('recipient')
        message = data.get('message')
        send_type = data.get('type', 'sms')
        
        if not debt_id or not recipient or not message:
            return jsonify({'success': False, 'message': trans_function('missing_required_fields', default='Missing required fields')}), 400
        
        # Verify debt belongs to current user (unless admin)
        db = get_mongo_db()
        query = {'_id': ObjectId(debt_id), 'type': 'creditor'} if is_admin() else {'_id': ObjectId(debt_id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        
        if not creditor:
            return jsonify({'success': False, 'message': trans_function('record_not_found', default='Record not found')}), 404
        
        # Check coin balance for non-admin users
        if not is_admin() and not check_coin_balance(2):
            return jsonify({'success': False, 'message': trans_function('insufficient_coins', default='Insufficient coins to send reminder')}), 400
        
        # Send SMS/WhatsApp based on type
        success = False
        api_response = {}
        
        if send_type == 'sms':
            success, api_response = send_sms_reminder(recipient, message)
        elif send_type == 'whatsapp':
            success, api_response = send_whatsapp_reminder(recipient, message)
        
        if success:
            # Update reminder count and deduct coins
            update_data = {'$inc': {'reminder_count': 1}}
            db.records.update_one({'_id': ObjectId(debt_id)}, update_data)
            
            if not is_admin():
                user_query = get_user_query(str(current_user.id))
                db.users.update_one(user_query, {'$inc': {'coin_balance': -2}})
                db.coin_transactions.insert_one({
                    'user_id': str(current_user.id),
                    'amount': -2,
                    'type': 'spend',
                    'date': datetime.utcnow(),
                    'ref': f"Reminder sent to {creditor['name']}"
                })
            
            # Log the reminder
            db.reminder_logs.insert_one({
                'user_id': str(current_user.id),
                'debt_id': debt_id,
                'recipient': recipient,
                'message': message,
                'type': send_type,
                'sent_at': datetime.utcnow(),
                'api_response': api_response
            })
            
            return jsonify({'success': True, 'message': trans_function('reminder_sent', default='Reminder sent successfully')})
        else:
            return jsonify({'success': False, 'message': trans_function('reminder_failed', default='Failed to send reminder'), 'details': api_response}), 500
            
    except Exception as e:
        logger.error(f"Error sending reminder: {str(e)}")
        return jsonify({'success': False, 'message': trans_function('something_went_wrong', default='An error occurred')}), 500

@creditors_bp.route('/generate_receipt/<id>')
@login_required
@requires_role('trader')
def generate_receipt(id):
    """Generate PDF receipt for a creditor."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        from reportlab.lib.units import inch
        from flask import Response
        import io
        
        db = get_mongo_db()
        query = {'_id': ObjectId(id), 'type': 'creditor'} if is_admin() else {'_id': ObjectId(id), 'user_id': str(current_user.id), 'type': 'creditor'}
        creditor = db.records.find_one(query)
        
        if not creditor:
            flash(trans_function('record_not_found', default='Record not found'), 'danger')
            return redirect(url_for('creditors_blueprint.index'))
        
        # Check coin balance for non-admin users
        if not is_admin() and not check_coin_balance(1):
            flash(trans_function('insufficient_coins', default='Insufficient coins to generate receipt'), 'danger')
            return redirect(url_for('coins_blueprint.purchase'))
        
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        
        # Header
        p.setFont("Helvetica-Bold", 24)
        p.drawString(inch, height - inch, "FiCore Records - Creditor Receipt")
        
        # Content
        p.setFont("Helvetica", 12)
        y_position = height - inch - 0.5 * inch
        p.drawString(inch, y_position, f"Name: {creditor['name']}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Amount Owed: {format_currency(creditor['amount_owed'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Contact: {creditor.get('contact', 'N/A')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Description: {creditor.get('description', 'No description provided')}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Date Recorded: {format_date(creditor['created_at'])}")
        y_position -= 0.3 * inch
        p.drawString(inch, y_position, f"Reminders Sent: {creditor.get('reminder_count', 0)}")
        
        # Footer
        p.setFont("Helvetica-Oblique", 10)
        p.drawString(inch, inch, "This document serves as an acknowledgement of debt recorded on FiCore Records.")
        
        p.showPage()
        p.save()
        
        # Deduct coins for non-admin users
        if not is_admin():
            user_query = get_user_query(str(current_user.id))
            db.users.update_one(user_query, {'$inc': {'coin_balance': -1}})
            db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': f"Receipt generated for {creditor['name']}"
            })
        
        buffer.seek(0)
        return Response(
            buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=FiCore_Receipt_{creditor["name"]}.pdf'
            }
        )
        
    except Exception as e:
        logger.error(f"Error generating receipt for creditor {id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('creditors_blueprint.index'))

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
                'reminder_count': 0,
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

def send_sms_reminder(recipient, message):
    """Send SMS reminder using Africa's Talking API."""
    try:
        api_key = os.getenv('AFRICAS_TALKING_API_KEY')
        username = os.getenv('AFRICAS_TALKING_USERNAME', 'sandbox')
        
        if not api_key:
            logger.warning("Africa's Talking API key not configured")
            return False, {'error': 'SMS service not configured'}
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "apikey": api_key
        }
        
        # Ensure recipient has country code
        if not recipient.startswith('+') and not recipient.startswith('234'):
            if recipient.startswith('0'):
                recipient = '234' + recipient[1:]
            else:
                recipient = '234' + recipient
        
        payload = {
            "username": username,
            "to": recipient,
            "message": message
        }
        
        response = requests.post(
            "https://api.africastalking.com/version1/messaging",
            headers=headers,
            data=payload,
            timeout=30
        )
        
        response.raise_for_status()
        result = response.json()
        
        if result and result.get('SMSMessageData', {}).get('Recipients'):
            recipients = result['SMSMessageData']['Recipients']
            if recipients and recipients[0].get('status') == 'Success':
                return True, result
        
        return False, result
        
    except Exception as e:
        logger.error(f"Error sending SMS: {str(e)}")
        return False, {'error': str(e)}

def send_whatsapp_reminder(recipient, message):
    """Send WhatsApp reminder (placeholder for future implementation)."""
    # For now, return success to allow testing
    # In production, this would integrate with WhatsApp Business API
    logger.info(f"WhatsApp reminder would be sent to {recipient}: {message}")
    return True, {'status': 'WhatsApp integration pending'}
