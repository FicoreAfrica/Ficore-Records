from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, FloatField, TextAreaField, SubmitField, validators
from utils import trans_function, requires_role, get_mongo_db, format_currency, format_date
from bson import ObjectId
from datetime import datetime
from werkzeug.security import generate_password_hash
import logging
import uuid

logger = logging.getLogger(__name__)

agents_bp = Blueprint('agents', __name__, url_prefix='/agents')

class RegisterTraderForm(FlaskForm):
    username = StringField(trans_function('username', default='Username'), [
        validators.DataRequired(message=trans_function('username_required', default='Username is required')),
        validators.Length(min=3, max=50, message=trans_function('username_length', default='Username must be between 3 and 50 characters'))
    ], render_kw={'class': 'form-control'})
    email = StringField(trans_function('email', default='Email'), [
        validators.DataRequired(message=trans_function('email_required', default='Email is required')),
        validators.Email(message=trans_function('email_invalid', default='Invalid email address'))
    ], render_kw={'class': 'form-control'})
    business_name = StringField(trans_function('business_name', default='Business Name'), [
        validators.DataRequired(message=trans_function('business_name_required', default='Business name is required'))
    ], render_kw={'class': 'form-control'})
    phone_number = StringField(trans_function('phone_number', default='Phone Number'), [
        validators.DataRequired(message=trans_function('phone_number_required', default='Phone number is required'))
    ], render_kw={'class': 'form-control'})
    industry = SelectField(trans_function('industry', default='Industry'), choices=[
        ('retail', trans_function('retail', default='Retail')),
        ('services', trans_function('services', default='Services')),
        ('manufacturing', trans_function('manufacturing', default='Manufacturing')),
        ('agriculture', trans_function('agriculture', default='Agriculture')),
        ('other', trans_function('other', default='Other'))
    ], validators=[validators.DataRequired()], render_kw={'class': 'form-select'})
    submit = SubmitField(trans_function('register_trader', default='Register Trader'), render_kw={'class': 'btn btn-primary w-100'})

class TokenManagementForm(FlaskForm):
    trader_username = StringField(trans_function('trader_username', default='Trader Username'), [
        validators.DataRequired(message=trans_function('trader_username_required', default='Trader username is required'))
    ], render_kw={'class': 'form-control'})
    token_amount = FloatField(trans_function('token_amount', default='Token Amount (₦)'), [
        validators.DataRequired(message=trans_function('token_amount_required', default='Token amount is required')),
        validators.NumberRange(min=100, message=trans_function('minimum_token_amount', default='Minimum token amount is ₦100'))
    ], render_kw={'class': 'form-control'})
    payment_method = SelectField(trans_function('payment_method', default='Payment Method'), choices=[
        ('cash', trans_function('cash', default='Cash')),
        ('bank_transfer', trans_function('bank_transfer', default='Bank Transfer')),
        ('mobile_money', trans_function('mobile_money', default='Mobile Money'))
    ], validators=[validators.DataRequired()], render_kw={'class': 'form-select'})
    notes = TextAreaField(trans_function('notes', default='Notes'), render_kw={'class': 'form-control', 'rows': 3})
    submit = SubmitField(trans_function('process_tokens', default='Process Tokens'), render_kw={'class': 'btn btn-success w-100'})

@agents_bp.route('/dashboard')
@login_required
@requires_role('agent')
def dashboard():
    """Agent main dashboard."""
    try:
        db = get_mongo_db()
        agent_id = current_user.id
        
        # Get agent's performance metrics
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Count traders registered by this agent
        traders_registered = db.users.count_documents({
            'role': 'trader',
            'registered_by_agent': agent_id
        })
        
        # Count token transactions facilitated today
        tokens_today = db.coin_transactions.count_documents({
            'facilitated_by_agent': agent_id,
            'date': {'$gte': today}
        })
        
        # Get recent activities
        recent_activities = list(db.agent_activities.find({
            'agent_id': agent_id
        }).sort('timestamp', -1).limit(10))
        
        # Get traders this agent has assisted
        assisted_traders = list(db.users.find({
            'role': 'trader',
            'assisted_by_agents': agent_id
        }).limit(5))
        
        for trader in assisted_traders:
            trader['_id'] = str(trader['_id'])
        
        for activity in recent_activities:
            activity['_id'] = str(activity['_id'])
        
        return render_template('agents/dashboard.html',
                             traders_registered=traders_registered,
                             tokens_today=tokens_today,
                             recent_activities=recent_activities,
                             assisted_traders=assisted_traders,
                             format_currency=format_currency,
                             format_date=format_date)
    except Exception as e:
        logger.error(f"Error loading agent dashboard for {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('index'))

@agents_bp.route('/register_trader', methods=['GET', 'POST'])
@login_required
@requires_role('agent')
def register_trader():
    """Register a new trader user."""
    form = RegisterTraderForm()
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            username = form.username.data.strip().lower()
            email = form.email.data.strip().lower()
            
            # Check if username or email already exists
            if db.users.find_one({'_id': username}):
                flash(trans_function('username_exists', default='Username already exists'), 'danger')
                return render_template('agents/register_trader.html', form=form)
            
            if db.users.find_one({'email': email}):
                flash(trans_function('email_exists', default='Email already exists'), 'danger')
                return render_template('agents/register_trader.html', form=form)
            
            # Generate temporary password
            temp_password = str(uuid.uuid4())[:8]
            
            # Create trader user
            trader_data = {
                '_id': username,
                'email': email,
                'password': generate_password_hash(temp_password),
                'role': 'trader',
                'coin_balance': 20,  # Bonus for agent registration
                'language': 'en',
                'setup_complete': False,
                'registered_by_agent': current_user.id,
                'business_details': {
                    'name': form.business_name.data.strip(),
                    'phone_number': form.phone_number.data.strip(),
                    'industry': form.industry.data
                },
                'created_at': datetime.utcnow()
            }
            
            db.users.insert_one(trader_data)
            
            # Log agent activity
            db.agent_activities.insert_one({
                'agent_id': current_user.id,
                'activity_type': 'trader_registration',
                'trader_id': username,
                'details': {
                    'business_name': form.business_name.data.strip(),
                    'industry': form.industry.data
                },
                'timestamp': datetime.utcnow()
            })
            
            # Credit signup bonus
            db.coin_transactions.insert_one({
                'user_id': username,
                'amount': 20,
                'type': 'credit',
                'ref': f"AGENT_SIGNUP_BONUS_{datetime.utcnow().isoformat()}",
                'facilitated_by_agent': current_user.id,
                'date': datetime.utcnow()
            })
            
            flash(trans_function('trader_registered_success', default=f'Trader registered successfully. Temporary password: {temp_password}'), 'success')
            logger.info(f"Agent {current_user.id} registered trader {username}")
            return redirect(url_for('agents_bp.dashboard'))
            
        except Exception as e:
            logger.error(f"Error registering trader by agent {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    
    return render_template('agents/register_trader.html', form=form)

@agents_bp.route('/manage_tokens', methods=['GET', 'POST'])
@login_required
@requires_role('agent')
def manage_tokens():
    """Facilitate token purchases for traders."""
    form = TokenManagementForm()
    if form.validate_on_submit():
        try:
            db = get_mongo_db()
            trader_username = form.trader_username.data.strip().lower()
            amount = form.token_amount.data
            
            # Verify trader exists
            trader = db.users.find_one({'_id': trader_username, 'role': 'trader'})
            if not trader:
                flash(trans_function('trader_not_found', default='Trader not found'), 'danger')
                return render_template('agents/manage_tokens.html', form=form)
            
            # Calculate coins (₦50 = 1 coin)
            coins = int(amount / 50)
            
            # Credit coins to trader
            db.users.update_one(
                {'_id': trader_username},
                {'$inc': {'coin_balance': coins}}
            )
            
            # Record transaction
            ref = f"AGENT_FACILITATED_{datetime.utcnow().isoformat()}"
            db.coin_transactions.insert_one({
                'user_id': trader_username,
                'amount': coins,
                'type': 'purchase',
                'ref': ref,
                'facilitated_by_agent': current_user.id,
                'payment_method': form.payment_method.data,
                'cash_amount': amount,
                'notes': form.notes.data,
                'date': datetime.utcnow()
            })
            
            # Log agent activity
            db.agent_activities.insert_one({
                'agent_id': current_user.id,
                'activity_type': 'token_facilitation',
                'trader_id': trader_username,
                'details': {
                    'amount': amount,
                    'coins': coins,
                    'payment_method': form.payment_method.data
                },
                'timestamp': datetime.utcnow()
            })
            
            flash(trans_function('tokens_processed_success', default=f'Successfully credited {coins} coins to {trader_username}'), 'success')
            logger.info(f"Agent {current_user.id} facilitated {coins} coins for trader {trader_username}")
            return redirect(url_for('agents_bp.manage_tokens'))
            
        except Exception as e:
            logger.error(f"Error processing tokens by agent {current_user.id}: {str(e)}")
            flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
    
    return render_template('agents/manage_tokens.html', form=form)

@agents_bp.route('/assist_trader_records/<trader_id>')
@login_required
@requires_role('agent')
def assist_trader_records(trader_id):
    """Assist a trader with their business records."""
    try:
        db = get_mongo_db()
        trader = db.users.find_one({'_id': trader_id, 'role': 'trader'})
        
        if not trader:
            flash(trans_function('trader_not_found', default='Trader not found'), 'danger')
            return redirect(url_for('agents_bp.dashboard'))
        
        # Mark agent as assisting this trader
        db.users.update_one(
            {'_id': trader_id},
            {'$addToSet': {'assisted_by_agents': current_user.id}}
        )
        
        # Get trader's recent records
        recent_debtors = list(db.records.find({
            'user_id': trader_id,
            'type': 'debtor'
        }).sort('created_at', -1).limit(5))
        
        recent_creditors = list(db.records.find({
            'user_id': trader_id,
            'type': 'creditor'
        }).sort('created_at', -1).limit(5))
        
        recent_cashflows = list(db.cashflows.find({
            'user_id': trader_id
        }).sort('created_at', -1).limit(5))
        
        # Convert ObjectIds to strings
        for record in recent_debtors + recent_creditors + recent_cashflows:
            record['_id'] = str(record['_id'])
        
        return render_template('agents/assist_trader_records.html',
                             trader=trader,
                             recent_debtors=recent_debtors,
                             recent_creditors=recent_creditors,
                             recent_cashflows=recent_cashflows,
                             format_currency=format_currency,
                             format_date=format_date)
        
    except Exception as e:
        logger.error(f"Error accessing trader records for agent {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('agents_bp.dashboard'))

@agents_bp.route('/generate_trader_report/<trader_id>')
@login_required
@requires_role('agent')
def generate_trader_report(trader_id):
    """Generate comprehensive report for a trader."""
    try:
        db = get_mongo_db()
        trader = db.users.find_one({'_id': trader_id, 'role': 'trader'})
        
        if not trader:
            flash(trans_function('trader_not_found', default='Trader not found'), 'danger')
            return redirect(url_for('agents_bp.dashboard'))
        
        # Calculate financial summary
        total_debtors = db.records.aggregate([
            {'$match': {'user_id': trader_id, 'type': 'debtor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ])
        total_debtors = list(total_debtors)
        total_debtors_amount = total_debtors[0]['total'] if total_debtors else 0
        
        total_creditors = db.records.aggregate([
            {'$match': {'user_id': trader_id, 'type': 'creditor'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount_owed'}}}
        ])
        total_creditors = list(total_creditors)
        total_creditors_amount = total_creditors[0]['total'] if total_creditors else 0
        
        total_receipts = db.cashflows.aggregate([
            {'$match': {'user_id': trader_id, 'type': 'receipt'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ])
        total_receipts = list(total_receipts)
        total_receipts_amount = total_receipts[0]['total'] if total_receipts else 0
        
        total_payments = db.cashflows.aggregate([
            {'$match': {'user_id': trader_id, 'type': 'payment'}},
            {'$group': {'_id': None, 'total': {'$sum': '$amount'}}}
        ])
        total_payments = list(total_payments)
        total_payments_amount = total_payments[0]['total'] if total_payments else 0
        
        # Log agent activity
        db.agent_activities.insert_one({
            'agent_id': current_user.id,
            'activity_type': 'report_generation',
            'trader_id': trader_id,
            'details': {
                'report_type': 'comprehensive_financial_summary'
            },
            'timestamp': datetime.utcnow()
        })
        
        return render_template('agents/generate_trader_report.html',
                             trader=trader,
                             total_debtors=total_debtors_amount,
                             total_creditors=total_creditors_amount,
                             total_receipts=total_receipts_amount,
                             total_payments=total_payments_amount,
                             net_position=total_debtors_amount - total_creditors_amount,
                             net_cashflow=total_receipts_amount - total_payments_amount,
                             format_currency=format_currency)
        
    except Exception as e:
        logger.error(f"Error generating trader report for agent {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('agents_bp.dashboard'))

@agents_bp.route('/my_activity')
@login_required
@requires_role('agent')
def my_activity():
    """View agent's own performance metrics and activity log."""
    try:
        db = get_mongo_db()
        agent_id = current_user.id
        
        # Get comprehensive metrics
        total_traders_registered = db.users.count_documents({
            'role': 'trader',
            'registered_by_agent': agent_id
        })
        
        total_tokens_facilitated = db.coin_transactions.aggregate([
            {'$match': {'facilitated_by_agent': agent_id}},
            {'$group': {'_id': None, 'total': {'$sum': '$cash_amount'}}}
        ])
        total_tokens_facilitated = list(total_tokens_facilitated)
        total_tokens_amount = total_tokens_facilitated[0]['total'] if total_tokens_facilitated else 0
        
        # Get activity history
        activities = list(db.agent_activities.find({
            'agent_id': agent_id
        }).sort('timestamp', -1).limit(50))
        
        for activity in activities:
            activity['_id'] = str(activity['_id'])
        
        return render_template('agents/my_activity.html',
                             total_traders_registered=total_traders_registered,
                             total_tokens_amount=total_tokens_amount,
                             activities=activities,
                             format_currency=format_currency,
                             format_date=format_date)
        
    except Exception as e:
        logger.error(f"Error loading agent activity for {current_user.id}: {str(e)}")
        flash(trans_function('something_went_wrong', default='An error occurred'), 'danger')
        return redirect(url_for('agents_bp.dashboard'))

@agents_bp.route('/api/search_traders')
@login_required
@requires_role('agent')
def search_traders():
    """API endpoint to search for traders."""
    try:
        query = request.args.get('q', '').strip()
        if len(query) < 2:
            return jsonify([])
        
        db = get_mongo_db()
        traders = list(db.users.find({
            'role': 'trader',
            '$or': [
                {'_id': {'$regex': query, '$options': 'i'}},
                {'business_details.name': {'$regex': query, '$options': 'i'}}
            ]
        }).limit(10))
        
        results = []
        for trader in traders:
            results.append({
                'id': trader['_id'],
                'username': trader['_id'],
                'business_name': trader.get('business_details', {}).get('name', 'N/A'),
                'email': trader['email']
            })
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error searching traders: {str(e)}")
        return jsonify([]), 500