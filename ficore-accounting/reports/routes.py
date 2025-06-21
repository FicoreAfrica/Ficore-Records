from flask import Blueprint, render_template, Response, flash, request
from flask_login import login_required, current_user
from utils import trans_function, requires_role, check_coin_balance, format_currency, format_date
from translations import trans_function
from app import mongo
from bson import ObjectId
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO
import csv
import logging

logger = logging.getLogger(__name__)

reports_bp = Blueprint('reports', __name__, url_prefix='/reports')

@reports_bp.route('/')
@login_required
@requires_role('trader')
def index():
    """Display report selection page."""
    try:
        return render_template('reports/index.html')
    except Exception as e:
        logger.error(f"Error loading reports index for user {current_user.id}: {str(e)}")
        flash(trans('something_went_wrong'), 'danger')
        return redirect(url_for('dashboard.index'))

@reports_bp.route('/profit_loss', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def profit_loss():
    """Generate profit/loss report with filters."""
    from app.forms import ReportForm
    form = ReportForm()
    if not check_coin_balance(1):
        flash(trans('insufficient_coins', default='Insufficient coins to generate a report. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    transactions = []
    query = {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            if form.start_date.data:
                query['date'] = {'$gte': form.start_date.data}
            if form.end_date.data:
                query['date'] = query.get('date', {}) | {'$lte': form.end_date.data}
            if form.category.data:
                query['category'] = form.category.data
            transactions = mongo.db.transactions.find(query).sort('date', -1)
            output_format = request.form.get('format', 'html')
            if output_format == 'pdf':
                return generate_profit_loss_pdf(transactions)
            elif output_format == 'csv':
                return generate_profit_loss_csv(transactions)
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$inc': {'coin_balance': -1}}
            )
            mongo.db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': 'Profit/Loss report generation'
            })
        except Exception as e:
            logger.error(f"Error generating profit/loss report for user {current_user.id}: {str(e)}")
            flash(trans('something_went_wrong'), 'danger')
    else:
        transactions = mongo.db.transactions.find(query).sort('date', -1)
    return render_template('reports/profit_loss.html', form=form, transactions=transactions, format_currency=format_currency, format_date=format_date)

@reports_bp.route('/inventory', methods=['GET', 'POST'])
@login_required
@requires_role('trader')
def inventory():
    """Generate inventory report with filters."""
    from app.forms import InventoryReportForm
    form = InventoryReportForm()
    if not check_coin_balance(1):
        flash(trans('insufficient_coins', default='Insufficient coins to generate a report. Purchase more coins.'), 'danger')
        return redirect(url_for('coins.purchase'))
    items = []
    query = {'user_id': str(current_user.id)}
    if form.validate_on_submit():
        try:
            if form.item_name.data:
                query['item_name'] = {'$regex': form.item_name.data, '$options': 'i'}
            items = mongo.db.inventory.find(query).sort('item_name', 1)
            output_format = request.form.get('format', 'html')
            if output_format == 'pdf':
                return generate_inventory_pdf(items)
            elif output_format == 'csv':
                return generate_inventory_csv(items)
            mongo.db.users.update_one(
                {'_id': ObjectId(current_user.id)},
                {'$inc': {'coin_balance': -1}}
            )
            mongo.db.coin_transactions.insert_one({
                'user_id': str(current_user.id),
                'amount': -1,
                'type': 'spend',
                'date': datetime.utcnow(),
                'ref': 'Inventory report generation'
            })
        except Exception as e:
            logger.error(f"Error generating inventory report for user {current_user.id}: {str(e)}")
            flash(trans('something_went_wrong'), 'danger')
    else:
        items = mongo.db.inventory.find(query).sort('item_name', 1)
    return render_template('reports/inventory.html', form=form, items=items, format_currency=format_currency)

def generate_profit_loss_pdf(transactions):
    """Generate PDF for profit/loss report."""
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, 10.5 * inch, trans('profit_loss_report', default='Profit/Loss Report'))
    p.drawString(1 * inch, 10.2 * inch, f"{trans('generated_on', default='Generated on')}: {format_date(datetime.utcnow())}")
    y = 9.5 * inch
    p.setFillColor(colors.black)
    p.drawString(1 * inch, y, trans('date', default='Date'))
    p.drawString(2.5 * inch, y, trans('party_name', default='Party Name'))
    p.drawString(4 * inch, y, trans('type', default='Type'))
    p.drawString(5 * inch, y, trans('amount', default='Amount'))
    p.drawString(6.5 * inch, y, trans('category', default='Category'))
    y -= 0.3 * inch
    total_income = 0
    total_expense = 0
    for t in transactions:
        p.drawString(1 * inch, y, format_date(t['date']))
        p.drawString(2.5 * inch, y, t['party_name'])
        p.drawString(4 * inch, y, trans(t['type'], default=t['type']))
        p.drawString(5 * inch, y, format_currency(t['amount']))
        p.drawString(6.5 * inch, y, trans(t['category'], default=t['category']))
        if t['type'] == 'receipt':
            total_income += t['amount']
        else:
            total_expense += t['amount']
        y -= 0.3 * inch
        if y < 1 * inch:
            p.showPage()
            y = 10.5 * inch
    y -= 0.3 * inch
    p.drawString(1 * inch, y, f"{trans('total_income', default='Total Income')}: {format_currency(total_income)}")
    y -= 0.3 * inch
    p.drawString(1 * inch, y, f"{trans('total_expense', default='Total Expense')}: {format_currency(total_expense)}")
    y -= 0.3 * inch
    p.drawString(1 * inch, y, f"{trans('net_profit', default='Net Profit')}: {format_currency(total_income - total_expense)}")
    p.showPage()
    p.save()
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=profit_loss.pdf'})

def generate_profit_loss_csv(transactions):
    """Generate CSV for profit/loss report."""
    output = []
    output.append([trans('date', default='Date'), trans('party_name', default='Party Name'), trans('type', default='Type'), trans('amount', default='Amount'), trans('category', default='Category')])
    total_income = 0
    total_expense = 0
    for t in transactions:
        output.append([format_date(t['date']), t['party_name'], trans(t['type'], default=t['type']), format_currency(t['amount']), trans(t['category'], default=t['category'])])
        if t['type'] == 'receipt':
            total_income += t['amount']
        else:
            total_expense += t['amount']
    output.append(['', '', '', f"{trans('total_income', default='Total Income')}: {format_currency(total_income)}", ''])
    output.append(['', '', '', f"{trans('total_expense', default='Total Expense')}: {format_currency(total_expense)}", ''])
    output.append(['', '', '', f"{trans('net_profit', default='Net Profit')}: {format_currency(total_income - total_expense)}", ''])
    buffer = BytesIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    return Response(buffer, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=profit_loss.csv'})

def generate_inventory_pdf(items):
    """Generate PDF for inventory report."""
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, 10.5 * inch, trans('inventory_report', default='Inventory Report'))
    p.drawString(1 * inch, 10.2 * inch, f"{trans('generated_on', default='Generated on')}: {format_date(datetime.utcnow())}")
    y = 9.5 * inch
    p.setFillColor(colors.black)
    p.drawString(1 * inch, y, trans('item_name', default='Item Name'))
    p.drawString(2.5 * inch, y, trans('quantity', default='Quantity'))
    p.drawString(3.5 * inch, y, trans('unit', default='Unit'))
    p.drawString(4.5 * inch, y, trans('buying_price', default='Buying Price'))
    p.drawString(5.5 * inch, y, trans('selling_price', default='Selling Price'))
    p.drawString(6.5 * inch, y, trans('threshold', default='Threshold'))
    y -= 0.3 * inch
    for item in items:
        p.drawString(1 * inch, y, item['item_name'])
        p.drawString(2.5 * inch, y, str(item['qty']))
        p.drawString(3.5 * inch, y, trans(item['unit'], default=item['unit']))
        p.drawString(4.5 * inch, y, format_currency(item['buying_price']))
        p.drawString(5.5 * inch, y, format_currency(item['selling_price']))
        p.drawString(6.5 * inch, y, str(item['threshold']))
        y -= 0.3 * inch
        if y < 1 * inch:
            p.showPage()
            y = 10.5 * inch
    p.showPage()
    p.save()
    buffer.seek(0)
    return Response(buffer, mimetype='application/pdf', headers={'Content-Disposition': 'attachment;filename=inventory.pdf'})

def generate_inventory_csv(items):
    """Generate CSV for inventory report."""
    output = []
    output.append([trans('item_name', default='Item Name'), trans('quantity', default='Quantity'), trans('unit', default='Unit'), trans('buying_price', default='Buying Price'), trans('selling_price', default='Selling Price'), trans('threshold', default='Threshold')])
    for item in items:
        output.append([item['item_name'], item['qty'], trans(item['unit'], default=item['unit']), format_currency(item['buying_price']), format_currency(item['selling_price']), item['threshold']])
    buffer = BytesIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows(output)
    buffer.seek(0)
    return Response(buffer, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=inventory.csv'})
