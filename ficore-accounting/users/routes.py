from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, jsonify, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField, validators
from flask_login import login_required, current_user, login_user, logout_user
from pymongo import errors
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
import logging
import uuid
from datetime import datetime, timedelta
from utils import trans_function, is_valid_email
import re
import random
from itsdangerous import URLSafeTimedSerializer
from app import limiter, check_coin_balance, mail
from bson import ObjectId

logger = logging.getLogger(__name__)

users_bp = Blueprint('users', __name__, template_folder='templates/users')

USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

class LoginForm(FlaskForm):
    username = StringField(trans('username', default='Username'), [
        validators.DataRequired(message=trans('username_required', default='Username is required')),
        validators.Length(min=3, max=50, message=trans('username_length', default='Username must be between 3 and 50 characters')),
        validators.Regexp(USERNAME_REGEX, message=trans('username_format', default='Username must be alphanumeric with underscores'))
    ], render_kw={'class': 'form-control'})
    password = PasswordField(trans('password', default='Password'), [
        validators.DataRequired(message=trans('password_required', default='Password is required')),
        validators.Length(min=8, message=trans('password_length', default='Password must be at least 8 characters'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('login', default='Login'), render_kw={'class': 'btn btn-primary w-100'})

class TwoFactorForm(FlaskForm):
    otp = StringField(trans('otp', default='One-Time Password'), [
        validators.DataRequired(message=trans('otp_required', default='OTP is required')),
        validators.Length(min=6, max=6, message=trans('otp_length', default='OTP must be 6 digits'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('verify_otp', default='Verify OTP'), render_kw={'class': 'btn btn-primary w-100'})

class SignupForm(FlaskForm):
    username = StringField(trans('username', default='Username'), [
        validators.DataRequired(message=trans('username_required', default='Username is required')),
        validators.Length(min=3, max=50, message=trans('username_length', default='Username must be between 3 and 50 characters')),
        validators.Regexp(USERNAME_REGEX, message=trans('username_format', default='Username must be alphanumeric with underscores'))
    ], render_kw={'class': 'form-control'})
    email = StringField(trans('email', default='Email'), [
        validators.DataRequired(message=trans('email_required', default='Email is required')),
        validators.Email(message=trans('email_invalid', default='Invalid email address')),
        validators.Length(max=254),
        lambda form, field: is_valid_email(field.data) or validators.ValidationError(trans('email_domain_invalid', default='Invalid email domain'))
    ], render_kw={'class': 'form-control'})
    password = PasswordField(trans('password', default='Password'), [
        validators.DataRequired(message=trans('password_required', default='Password is required')),
        validators.Length(min=8, message=trans('password_length', default='Password must be at least 8 characters')),
        validators.Regexp(PASSWORD_REGEX, message=trans('password_format', default='Password must include uppercase, lowercase, number, and special character'))
    ], render_kw={'class': 'form-control'})
    role = SelectField(trans('role', default='Role'), choices=[
        ('personal', trans('personal', default='Personal')),
        ('trader', trans('trader', default='Trader')),
        ('agent', trans('agent', default='Agent'))
    ], validators=[validators.DataRequired(message=trans('role_required', default='Role is required'))], render_kw={'class': 'form-select'})
    language = SelectField(trans('language', default='Language'), choices=[
        ('en', trans('english', default='English')),
        ('ha', trans('hausa', default='Hausa'))
    ], validators=[validators.DataRequired(message=trans('language_required', default='Language is required'))], render_kw={'class': 'form-select'})
    submit = SubmitField(trans('signup', default='Sign Up'), render_kw={'class': 'btn btn-primary w-100'})

class ForgotPasswordForm(FlaskForm):
    email = StringField(trans('email', default='Email'), [
        validators.DataRequired(message=trans('email_required', default='Email is required')),
        validators.Email(message=trans('email_invalid', default='Invalid email address'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('send_reset_link', default='Send Reset Link'), render_kw={'class': 'btn btn-primary w-100'})

class ResetPasswordForm(FlaskForm):
    password = PasswordField(trans('password', default='Password'), [
        validators.DataRequired(message=trans('password_required', default='Password is required')),
        validators.Length(min=8, message=trans('password_length', default='Password must be at least 8 characters')),
        validators.Regexp(PASSWORD_REGEX, message=trans('password_format', default='Password must include uppercase, lowercase, number, and special character'))
    ], render_kw={'class': 'form-control'})
    confirm_password = PasswordField(trans('confirm_password', default='Confirm Password'), [
        validators.DataRequired(message=trans('confirm_password_required', default='Confirm password is required')),
        validators.EqualTo('password', message=trans('passwords_must_match', default='Passwords must match'))
    ], render_kw={'class': 'form-control'})
    submit = SubmitField(trans('reset_password', default='Reset Password'), render_kw={'class': 'btn btn-primary w-100'})

class ProfileForm(FlaskForm):
    email = StringField(trans('email', default='Email'), [
        validators.DataRequired(message=trans('email_required', default='Email is required')),
        validators.Email(message=trans('email_invalid', default='Invalid email address'))
    ], render_kw={'class': 'form-control'})
    display_name = StringField(trans('display_name', default='Display Name'), [
        validators.DataRequired(message=trans('display_name_required', default='Display Name is required')),
        validators.Length(min=3, max=50, message=trans('display_name_length', default='Display Name must be between 3 and 50 characters'))
    ], render_kw={'class': 'form-control'})
    language = SelectField(trans('language', default='Language'), choices=[
        ('en', trans('english', default='English')),
        ('ha', trans('hausa', default='Hausa'))
    ], validators=[validators.DataRequired(message=trans('language_required', default='Language is required'))], render_kw={'class': 'form-select'})
    submit = SubmitField(trans('update_profile', default='Update Profile'), render_kw={'class': 'btn btn-primary w-100'})

class BusinessSetupForm(FlaskForm):
    business_name = StringField(trans('business_name', default='Business Name'), 
                              validators=[validators.DataRequired(), validators.Length(min=2, max=100)], render_kw={'class': 'form-control'})
    address = TextAreaField(trans('business_address', default='Business Address'), 
                           validators=[validators.DataRequired(), validators.Length(max=500)], render_kw={'class': 'form-control'})
    industry = SelectField(trans('industry', default='Industry'), 
                         choices=[
                             ('retail', trans('retail', default='Retail')),
                             ('services', trans('services', default='Services')),
                             ('manufacturing', trans('manufacturing', default='Manufacturing')),
                             ('other', trans('other', default='Other'))
                         ], 
                         validators=[validators.DataRequired()], render_kw={'class': 'form-select'})
    submit = SubmitField(trans('save_and_continue', default='Save and Continue'), render_kw={'class': 'btn btn-primary w-100'})

def log_audit_action(action, details):
    try:
        mongo = current_app.extensions['pymongo']
        mongo.db.audit_logs.insert_one({
            'admin_id': current_user.id if current_user.is_authenticated else 'system',
            'action': action,
            'details': details,
            'timestamp': datetime.utcnow()
        })
    except Exception as e:
        logger.error(f"Error logging audit action: {str(e)}")

@users_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        try:
            mongo = current_app.extensions['pymongo']
            username = form.username.data.strip().lower()
            if not USERNAME_REGEX.match(username):
                flash(trans('username_format', default='Invalid username format'), 'danger')
                logger.warning(f"Invalid username format: {username}")
                return render_template('users/login.html', form=form)
            user = mongo.db.users.find_one({'_id': username})
            if user and check_password_hash(user['password'], form.password.data):
                if os.getenv('ENABLE_2FA', 'false').lower() == 'true':
                    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
                    mongo.db.users.update_one(
                        {'_id': username},
                        {'$set': {'otp': otp, 'otp_expiry': datetime.utcnow() + timedelta(minutes=5)}}
                    )
                    msg = Message(
                        subject=trans('otp_subject', default='Your One-Time Password'),
                        recipients=[user['email']],
                        body=trans('otp_body', default=f'Your OTP is {otp}. It expires in 5 minutes.')
                    )
                    mail.send(msg)
                    session['pending_user_id'] = username
                    return redirect(url_for('users.verify_2fa'))
                from app import User
                login_user(User(user['_id'], user['email'], user.get('display_name'), user.get('role', 'personal')), remember=True)
                session['lang'] = user.get('language', 'en')
                log_audit_action('login', {'user_id': username})
                logger.info(f"User {username} logged in successfully")
                if not user.get('setup_complete', False):
                    return redirect(url_for('users.setup_wizard'))
                return redirect(url_for('users.profile'))
            flash(trans('invalid_credentials', default='Invalid username or password'), 'danger')
            logger.warning(f"Failed login attempt for username: {username}")
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during login: {str(e)}")
            flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('users/login.html', form=form), 500
    return render_template('users/login.html', form=form)

@users_bp.route('/verify_2fa', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def verify_2fa():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if 'pending_user_id' not in session:
        return redirect(url_for('users.login'))
    form = TwoFactorForm()
    if form.validate_on_submit():
        try:
            mongo = current_app.extensions['pymongo']
            username = session['pending_user_id']
            user = mongo.db.users.find_one({'_id': username})
            if user and user.get('otp') == form.otp.data and user.get('otp_expiry') > datetime.utcnow():
                from app import User
                login_user(User(user['_id'], user['email'], user.get('display_name'), user.get('role', 'personal')), remember=True)
                session['lang'] = user.get('language', 'en')
                mongo.db.users.update_one(
                    {'_id': username},
                    {'$unset': {'otp': '', 'otp_expiry': ''}}
                )
                log_audit_action('verify_2fa', {'user_id': username})
                logger.info(f"User {username} verified 2FA successfully")
                session.pop('pending_user_id')
                if not user.get('setup_complete', False):
                    return redirect(url_for('users.setup_wizard'))
                return redirect(url_for('users.profile'))
            flash(trans('invalid_otp', default='Invalid or expired OTP'), 'danger')
            logger.warning(f"Failed 2FA attempt for username: {username}")
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during 2FA verification: {str(e)}")
            flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('users/verify_2fa.html', form=form), 500
    return render_template('users/verify_2fa.html', form=form)

@users_bp.route('/signup', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = SignupForm()
    if form.validate_on_submit():
        try:
            mongo = current_app.extensions['pymongo']
            username = form.username.data.strip().lower()
            email = form.email.data.strip().lower()
            role = form.role.data
            language = form.language.data
            if mongo.db.users.find_one({'_id': username}) or mongo.db.users.find_one({'email': email}):
                flash(trans('user_exists', default='Username or email already exists'), 'danger')
                return render_template('users/signup.html', form=form)
            user_data = {
                '_id': username,
                'email': email,
                'password': generate_password_hash(form.password.data),
                'role': role,
                'coin_balance': 10,  # Grant 10 free coins
                'language': language,
                'dark_mode': False,
                'is_admin': role == 'admin',
                'setup_complete': False,
                'display_name': username,
                'created_at': datetime.utcnow()
            }
            result = mongo.db.users.insert_one(user_data)
            mongo.db.coin_transactions.insert_one({
                'user_id': username,
                'amount': 10,
                'type': 'credit',
                'ref': f"SIGNUP_BONUS_{datetime.utcnow().isoformat()}",
                'date': datetime.utcnow()
            })
            log_audit_action('signup', {'user_id': username, 'role': role})
            from app import User
            login_user(User(username, email, username, role), remember=True)
            session['lang'] = language
            logger.info(f"New user created: {username} (role: {role})")
            return redirect(url_for('users.setup_wizard'))
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during signup: {str(e)}")
            flash(trans('signup_error', default='Error during signup'), 'danger')
            return render_template('users/signup.html', form=form), 500
    return render_template('users/signup.html', form=form)

@users_bp.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        try:
            mongo = current_app.extensions['pymongo']
            email = form.email.data.strip().lower()
            user = mongo.db.users.find_one({'email': email})
            if not user:
                flash(trans('email_not_found', default='Email not found'), 'danger')
                return render_template('users/forgot_password.html', form=form)
            reset_token = URLSafeTimedSerializer(current_app.config['SECRET_KEY']).dumps(email, salt='reset-salt')
            expiry = datetime.utcnow() + timedelta(minutes=15)
            mongo.db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'reset_token': reset_token, 'reset_token_expiry': expiry}}
            )
            reset_url = url_for('users.reset_password', token=reset_token, _external=True)
            msg = Message(
                subject=trans('reset_password_subject', default='Reset Your Password'),
                recipients=[email],
                body=trans('reset_password_body', default=f'Click the link to reset your password: {reset_url}\nLink expires in 15 minutes.')
            )
            mail.send(msg)
            log_audit_action('forgot_password', {'email': email})
            flash(trans('reset_email_sent', default='Password reset email sent'), 'success')
            return render_template('users/forgot_password.html', form=form)
        except Exception as e:
            logger.error(f"Error during forgot password: {str(e)}")
            flash(trans('forgot_password_error', default='Error processing request'), 'danger')
            return render_template('users/forgot_password.html', form=form), 500
    return render_template('users/forgot_password.html', form=form)

@users_bp.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def reset_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    token = request.args.get('token')
    try:
        email = URLSafeTimedSerializer(current_app.config['SECRET_KEY']).loads(token, salt='reset-salt', max_age=900)
    except Exception:
        flash(trans('invalid_or_expired_token', default='Invalid or expired token'), 'danger')
        return redirect(url_for('users.forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            mongo = current_app.extensions['pymongo']
            user = mongo.db.users.find_one({'email': email})
            if not user:
                flash(trans('invalid_or_expired_token', default='Invalid or expired token'), 'danger')
                return render_template('users/reset_password.html', form=form, token=token)
            mongo.db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'password': generate_password_hash(form.password.data)}, 
                 '$unset': {'reset_token': '', 'reset_token_expiry': ''}}
            )
            log_audit_action('reset_password', {'user_id': user['_id']})
            flash(trans('reset_password_success', default='Password reset successfully'), 'success')
            return redirect(url_for('users.login'))
        except Exception as e:
            logger.error(f"Error during password reset: {str(e)}")
            flash(trans('reset_password_error', default='Error resetting password'), 'danger')
            return render_template('users/reset_password.html', form=form, token=token), 500
    return render_template('users/reset_password.html', form=form, token=token)

@users_bp.route('/profile', methods=['GET', 'POST'])
@login_required
@limiter.limit("50 per hour")
def profile():
    try:
        mongo = current_app.extensions['pymongo']
        user = mongo.db.users.find_one({'_id': current_user.id})
        if not user:
            flash(trans('user_not_found', default='User not found'), 'danger')
            return redirect(url_for('index'))
        form = ProfileForm(data={
            'email': user['email'],
            'display_name': user['display_name'],
            'language': user.get('language', 'en')
        })
        if form.validate_on_submit():
            try:
                if not check_coin_balance(1):
                    flash(trans('insufficient_coins', default='Insufficient coins to update profile'), 'danger')
                    return redirect(url_for('coins.purchase'))
                new_email = form.email.data.strip().lower()
                new_display_name = form.display_name.data.strip()
                new_language = form.language.data
                if new_email != user['email'] and mongo.db.users.find_one({'email': new_email}):
                    flash(trans('email_exists', default='Email already exists'), 'danger')
                    return render_template('users/profile.html', form=form, user=user)
                mongo.db.users.update_one(
                    {'_id': current_user.id},
                    {
                        '$set': {
                            'email': new_email,
                            'display_name': new_display_name,
                            'language': new_language,
                            'updated_at': datetime.utcnow()
                        },
                        '$inc': {'coin_balance': -1}
                    }
                )
                mongo.db.coin_transactions.insert_one({
                    'user_id': current_user.id,
                    'amount': -1,
                    'type': 'spend',
                    'ref': f"PROFILE_UPDATE_{datetime.utcnow().isoformat()}",
                    'date': datetime.utcnow()
                })
                log_audit_action('update_profile', {'user_id': current_user.id})
                current_user.email = new_email
                current_user.display_name = new_display_name
                session['lang'] = new_language
                flash(trans('profile_updated', default='Profile updated successfully'), 'success')
                logger.info(f"Profile updated for user: {current_user.id}")
                return redirect(url_for('users.profile'))
            except errors.PyMongoError as e:
                logger.error(f"MongoDB error updating profile: {str(e)}")
                flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
                return render_template('users/profile.html', form=form, user=user), 500
        user['_id'] = str(user['_id'])
        user['coin_balance'] = user.get('coin_balance', 0)
        return render_template('users/profile.html', form=form, user=user)
    except errors.PyMongoError as e:
        logger.error(f"MongoDB error fetching profile: {str(e)}")
        flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('index')), 500

@users_bp.route('/setup_wizard', methods=['GET', 'POST'])
@login_required
@limiter.limit("50 per hour")
def setup_wizard():
    mongo = current_app.extensions['pymongo']
    user = mongo.db.users.find_one({'_id': current_user.id})
    if user.get('setup_complete', False):
        return redirect(url_for('general_dashboard'))
    form = BusinessSetupForm()
    if form.validate_on_submit():
        try:
            if not check_coin_balance(1):
                flash(trans('insufficient_coins', default='Insufficient coins to complete setup'), 'danger')
                return redirect(url_for('coins.purchase'))
            mongo.db.users.update_one(
                {'_id': current_user.id},
                {
                    '$set': {
                        'business_details': {
                            'name': form.business_name.data.strip(),
                            'address': form.address.data.strip(),
                            'industry': form.industry.data
                        },
                        'setup_complete': True
                    },
                    '$inc': {'coin_balance': -1}
                }
            )
            mongo.db.coin_transactions.insert_one({
                'user_id': current_user.id,
                'amount': -1,
                'type': 'spend',
                'ref': f"SETUP_WIZARD_{datetime.utcnow().isoformat()}",
                'date': datetime.utcnow()
            })
            log_audit_action('complete_setup_wizard', {'user_id': current_user.id})
            flash(trans('business_setup_completed', default='Business setup completed'), 'success')
            logger.info(f"Business setup completed for user: {current_user.id}")
            return redirect(url_for('users.profile'))
        except errors.PyMongoError as e:
            logger.error(f"MongoDB error during business setup: {str(e)}")
            flash(trans('core_something_went_wrong', default='An error occurred'), 'danger')
            return render_template('users/setup.html', form=form), 500
    return render_template('users/setup.html', form=form)

@users_bp.route('/logout')
@login_required
@limiter.limit("100 per hour")
def logout():
    user_id = current_user.id
    logout_user()
    log_audit_action('logout', {'user_id': user_id})
    flash(trans('logged_out', default='Logged out successfully'), 'success')
    session.clear()
    return redirect(url_for('index'))

@users_bp.route('/auth/signin')
def signin():
    return redirect(url_for('users.login'))

@users_bp.route('/auth/signup')
def signup_redirect():
    return redirect(url_for('users.signup'))

@users_bp.route('/auth/forgot-password')
def forgot_password_redirect():
    return redirect(url_for('users.forgot_password'))

@users_bp.route('/auth/reset-password')
def reset_password_redirect():
    return redirect(url_for('users.reset_password'))

@users_bp.before_app_request
def check_wizard_completion():
    if request.endpoint and 'static' in request.endpoint:
        return
    if not current_user.is_authenticated:
        if request.endpoint not in ['users.login', 'users.signup', 'users.forgot_password', 
                                   'users.reset_password', 'users.verify_2fa', 'users.signin', 
                                   'users.signup_redirect', 'users.forgot_password_redirect', 
                                   'users.reset_password_redirect', 'index', 'about']:
            flash(trans('login_required', default='Please log in'), 'danger')
            return redirect(url_for('users.login'))
    elif current_user.is_authenticated:
        mongo = current_app.extensions['pymongo']
        user = mongo.db.users.find_one({'_id': current_user.id})
        if user and not user.get('setup_complete', False):
            if request.endpoint not in ['users.setup_wizard', 'users.logout', 'users.profile', 
                                       'coins.purchase', 'coins.get_balance', 'set_language', 
                                       'set_dark_mode']:
                return redirect(url_for('users.setup_wizard'))
