from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user
from utils import trans_function, requires_role, is_valid_email, format_currency, get_mongo_db, is_admin
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
    from app.forms import ProfileForm
    form = ProfileForm(data={
        'name': current_user.name,
        'email': current_user.email,
        'phone': current_user.phone
    })
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            # TEMPORARY: Allow admin to update any profile during testing
            # TODO: Restore original user_id filter {'_id': ObjectId(current_user.id)} for production
            user_id = ObjectId(request.args.get('user_id', current_user.id)) if is_admin() and request.args.get('user_id') else ObjectId(current_user.id)
            if form.email.data != current_user.email and db.users.find_one({'email': form.email.data}):
                flash(trans_function('email_exists', default='Email already in use'), 'danger')
                return render_template('settings/profile.html', form=form)
            update_data = {
                'name': form.name.data,
                'email': form.email.data,
                'phone': form.phone.data,
                'updated_at': datetime.utcnow()
            }
            db.users.update_one(
                {'_id': user_id},
                {'$set': update_data}
            )
            flash(trans_function('profile_updated', default='Profile updated successfully'), 'success')
            return redirect(url_for('settings_blueprint.index'))
        except Exception as e:
            logger.error(f"Error updating profile for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('settings/profile.html', form=form)

@settings_bp.route('/notifications', methods=['GET', 'POST'])
@login_required
def notifications():
    """Update notification preferences."""
    from app.forms import NotificationForm
    form = NotificationForm(data={
        'email_notifications': current_user.get('email_notifications', True),
        'sms_notifications': current_user.get('sms_notifications', False)
    })
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            # TEMPORARY: Allow admin to update any user's notifications during testing
            # TODO: Restore original user_id filter {'_id': ObjectId(current_user.id)} for production
            user_id = ObjectId(request.args.get('user_id', current_user.id)) if is_admin() and request.args.get('user_id') else ObjectId(current_user.id)
            update_data = {
                'email_notifications': form.email_notifications.data,
                'sms_notifications': form.sms_notifications.data,
                'updated_at': datetime.utcnow()
            }
            db.users.update_one(
                {'_id': user_id},
                {'$set': update_data}
            )
            flash(trans_function('notifications_updated', default='Notification preferences updated successfully'), 'success')
            return redirect(url_for('settings_blueprint.index'))
        except Exception as e:
            logger.error(f"Error updating notifications for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('settings/notifications.html', form=form)

@settings_bp.route('/language', methods=['GET', 'POST'])
@login_required
def language():
    """Update language preference."""
    from app.forms import LanguageForm
    form = LanguageForm(data={'language': session.get('language', 'en')})
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            # TEMPORARY: Allow admin to update any user's language during testing
            # TODO: Restore original user_id filter {'_id': ObjectId(current_user.id)} for production
            user_id = ObjectId(request.args.get('user_id', current_user.id)) if is_admin() and request.args.get('user_id') else ObjectId(current_user.id)
            session['language'] = form.language.data
            db.users.update_one(
                {'_id': user_id},
                {'$set': {'language': form.language.data, 'updated_at': datetime.utcnow()}}
            )
            flash(trans_function('language_updated', default='Language updated successfully'), 'success')
            return redirect(url_for('settings_blueprint.index'))
        except Exception as e:
            logger.error(f"Error updating language for user {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    return render_template('settings/language.html', form=form)
