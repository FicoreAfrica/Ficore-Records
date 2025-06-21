from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_required, current_user
from utils import trans_function, requires_role, is_valid_email, format_currency
from app import mongo
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
        flash(trans('something_went_wrong'), 'danger')
        return redirect(url_for('dashboard.index'))

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
            if form.email.data != current_user.email and mongo.db.users.find_one({'email': form.email.data}):
                flash(trans('email_exists', default='Email already in use'), 'danger')
                return render_template('settings/profile.html', form=form)
            update_data = {
                'name': form.name.data,
                'email': form.email.data,
                'phone': form.phone.data,
                'updated_at': datetime.utcnow()
            }
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': update_data}
            )
            flash(trans('profile_updated', default='Profile updated successfully'), 'success')
            return redirect(url_for('settings.index'))
        except Exception as e:
            logger.error(f"Error updating profile for user {current_user.id}: {str(e)}")
            flash(trans('something_went_wrong'), 'danger')
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
            update_data = {
                'email_notifications': form.email_notifications.data,
                'sms_notifications': form.sms_notifications.data,
                'updated_at': datetime.utcnow()
            }
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': update_data}
            )
            flash(trans('notifications_updated', default='Notification preferences updated successfully'), 'success')
            return redirect(url_for('settings.index'))
        except Exception as e:
            logger.error(f"Error updating notifications for user {current_user.id}: {str(e)}")
            flash(trans('something_went_wrong'), 'danger')
    return render_template('settings/notifications.html', form=form)

@settings_bp.route('/language', methods=['GET', 'POST'])
@login_required
def language():
    """Update language preference."""
    from app.forms import LanguageForm
    form = LanguageForm(data={'language': session.get('language', 'en')})
    if form.validate_on_submit():
        try:
            session['language'] = form.language.data
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$set': {'language': form.language.data, 'updated_at': datetime.utcnow()}}
            )
            flash(trans('language_updated', default='Language updated successfully'), 'success')
            return redirect(url_for('settings.index'))
        except Exception as e:
            logger.error(f"Error updating language for user {current_user.id}: {str(e)}")
            flash(trans('something_went_wrong'), 'danger')
    return render_template('settings/language.html', form=form)
