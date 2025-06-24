from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user
from utils import trans_function, requires_role, is_valid_email, format_currency, get_mongo_db, is_admin, get_user_query
from bson import ObjectId
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')

@settings_bp.route('/')
@login_required
def index():
    """Display settings overview."""
    try:
        return render_template('settings/index.html', user=current_user)
    except Exception as e:
        logger.error(f"Error loading settings for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('dashboard_blueprint.index'))

@settings_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Update user profile."""
    from flask_wtf import FlaskForm
    from wtforms import StringField, SubmitField, validators
    
    class ProfileForm(FlaskForm):
        name = StringField('Name', validators=[validators.DataRequired()])
        email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
        phone = StringField('Phone', validators=[validators.Optional()])
        submit = SubmitField('Save')
    
    try:
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        
        form = ProfileForm(data={
            'name': user.get('display_name', ''),
            'email': user.get('email', ''),
            'phone': user.get('phone', '')
        })
        
        if form.validate_on_submit():
            try:
                if form.email.data != user['email'] and db.users.find_one({'email': form.email.data}):
                    flash(trans_function('email_exists', default='Email already in use'), 'danger')
                    return render_template('settings/profile.html', form=form)
                update_data = {
                    'display_name': form.name.data,
                    'email': form.email.data,
                    'phone': form.phone.data,
                    'updated_at': datetime.utcnow()
                }
                db.users.update_one(
                    user_query,
                    {'$set': update_data}
                )
                flash(trans_function('profile_updated', default='Profile updated successfully'), 'success')
                return redirect(url_for('settings_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating profile for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('settings/profile.html', form=form)
    except Exception as e:
        logger.error(f"Error in profile settings for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('settings_blueprint.index'))

@settings_bp.route('/notifications', methods=['GET', 'POST'])
@login_required
def notifications():
    """Update notification preferences."""
    from flask_wtf import FlaskForm
    from wtforms import BooleanField, SubmitField
    
    class NotificationForm(FlaskForm):
        email_notifications = BooleanField('Email Notifications')
        sms_notifications = BooleanField('SMS Notifications')
        submit = SubmitField('Save')
    
    try:
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        
        form = NotificationForm(data={
            'email_notifications': user.get('email_notifications', True),
            'sms_notifications': user.get('sms_notifications', False)
        })
        
        if form.validate_on_submit():
            try:
                update_data = {
                    'email_notifications': form.email_notifications.data,
                    'sms_notifications': form.sms_notifications.data,
                    'updated_at': datetime.utcnow()
                }
                db.users.update_one(
                    user_query,
                    {'$set': update_data}
                )
                flash(trans_function('notifications_updated', default='Notification preferences updated successfully'), 'success')
                return redirect(url_for('settings_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating notifications for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('settings/notifications.html', form=form)
    except Exception as e:
        logger.error(f"Error in notification settings for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('settings_blueprint.index'))

@settings_bp.route('/language', methods=['GET', 'POST'])
@login_required
def language():
    """Update language preference."""
    from flask_wtf import FlaskForm
    from wtforms import SelectField, SubmitField, validators
    
    class LanguageForm(FlaskForm):
        language = SelectField('Language', choices=[
            ('en', 'English'),
            ('ha', 'Hausa')
        ], validators=[validators.DataRequired()])
        submit = SubmitField('Save')
    
    try:
        db = get_mongo_db()
        user_id = request.args.get('user_id', current_user.id) if is_admin() and request.args.get('user_id') else current_user.id
        user_query = get_user_query(user_id)
        user = db.users.find_one(user_query)
        
        form = LanguageForm(data={'language': user.get('language', 'en')})
        
        if form.validate_on_submit():
            try:
                session['lang'] = form.language.data
                db.users.update_one(
                    user_query,
                    {'$set': {'language': form.language.data, 'updated_at': datetime.utcnow()}}
                )
                flash(trans_function('language_updated', default='Language updated successfully'), 'success')
                return redirect(url_for('settings_blueprint.index'))
            except Exception as e:
                logger.error(f"Error updating language for user {current_user.id}: {str(e)}")
                flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return render_template('settings/language.html', form=form)
    except Exception as e:
        logger.error(f"Error in language settings for user {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('settings_blueprint.index'))
