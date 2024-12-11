from flask import Flask, render_template, redirect, url_for, flash, request, make_response, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from models import db, User, GlucoseLog, InsulinLog, MealLog
from forms import RegistrationForm, LoginForm, GlucoseLogForm, InsulinLogForm, MealLogForm, UserSettingsForm
from xhtml2pdf import pisa
from io import BytesIO
from datetime import datetime, timedelta
import logging
from flask_mail import Mail, Message

# Logging configuration
logging.basicConfig(level=logging.DEBUG)

# Flask app initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diabetes_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

# Initialize extensions
db.init_app(app)
csrf = CSRFProtect(app)
mail = Mail(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load the logged-in user by their ID."""
    return db.session.get(User, int(user_id))


# Jinja2 template filter for formatting dates
@app.template_filter('strftime')
def format_datetime(value, format='%Y-%m-%d %H:%M'):
    """Format datetime values for templates."""
    if value is None:
        return ''
    return value.strftime(format)


# Error handler for 404 (Page Not Found)
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors gracefully."""
    logging.error(f"404 Error: {e}")
    flash("Page not found.", "danger")
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# Generic error handler for unexpected exceptions
@app.errorhandler(Exception)
def handle_exception(e):
    """Handle unexpected exceptions."""
    logging.error(f"Unexpected error: {e}")
    flash("An unexpected error occurred. Please try again.", "danger")
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# Home route
@app.route('/')
def home():
    """Redirect users to the dashboard if logged in, otherwise to login."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))

        # Create and save new user
        user = User(email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid email or password.", "danger")
    return render_template('login.html', form=form)


# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard showing analytics and recent logs."""
    today = datetime.now().date()
    one_week_ago = today - timedelta(days=7)
    one_month_ago = today - timedelta(days=30)
    one_year_ago = today - timedelta(days=365)

    try:
        # Fetch recent glucose logs
        recent_glucose_logs = GlucoseLog.query.filter_by(user_id=current_user.id).order_by(GlucoseLog.timestamp.desc()).limit(5).all()
        avg_glucose = db.session.query(db.func.avg(GlucoseLog.glucose_level)).filter_by(user_id=current_user.id).scalar() or 0

        # Fetch recent insulin logs
        recent_insulin_logs = InsulinLog.query.filter_by(user_id=current_user.id).order_by(InsulinLog.timestamp.desc()).limit(5).all()
        total_insulin = db.session.query(db.func.sum(InsulinLog.insulin_units)).filter_by(user_id=current_user.id).scalar() or 0
        weekly_insulin = db.session.query(db.func.sum(InsulinLog.insulin_units)).filter(
            InsulinLog.user_id == current_user.id,
            InsulinLog.timestamp >= one_week_ago
        ).scalar() or 0
        monthly_insulin = db.session.query(db.func.sum(InsulinLog.insulin_units)).filter(
            InsulinLog.user_id == current_user.id,
            InsulinLog.timestamp >= one_month_ago
        ).scalar() or 0

    except Exception as e:
        logging.error(f"Error fetching data for dashboard: {e}")
        flash("An error occurred while fetching data for the dashboard.", "danger")
        return redirect(url_for('home'))

    return render_template(
        'dashboard.html',
        recent_glucose_logs=recent_glucose_logs,
        avg_glucose=avg_glucose,
        recent_insulin_logs=recent_insulin_logs,
        total_insulin=total_insulin,
        weekly_insulin=weekly_insulin,
        monthly_insulin=monthly_insulin
    )


# Profile route
@app.route('/profile')
@login_required
def profile():
    """Display user profile information."""
    return render_template('profile.html', user=current_user)


# Settings route
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Display and update user settings."""
    form = UserSettingsForm(obj=current_user)
    if form.validate_on_submit():
        current_user.insulin_to_carb_ratio = form.insulin_to_carb_ratio.data
        current_user.target_glucose = form.target_glucose.data
        db.session.commit()
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', form=form)


# Log blood glucose route
@app.route('/log_blood_glucose', methods=['GET', 'POST'])
@login_required
def log_blood_glucose():
    """Log blood glucose levels."""
    form = GlucoseLogForm()
    if form.validate_on_submit():
        log = GlucoseLog(user_id=current_user.id, glucose_level=form.glucose_level.data)
        db.session.add(log)
        db.session.commit()

        # Send alert for abnormal glucose levels
        if log.glucose_level < 4.0 or log.glucose_level > 180:
            msg = Message(
                subject="Alert: Abnormal Glucose Level",
                sender=app.config['MAIL_USERNAME'],
                recipients=[current_user.email],
                body=f"Your glucose level of {log.glucose_level} mg/dL is abnormal."
            )
            mail.send(msg)

        flash("Blood glucose level logged successfully.", "success")
        return redirect(url_for('dashboard'))
    return render_template('log_blood_glucose.html', form=form)


# Log insulin route
@app.route('/log_insulin', methods=['GET', 'POST'])
@login_required
def log_insulin():
    """Log insulin doses."""
    form = InsulinLogForm()
    if form.validate_on_submit():
        log = InsulinLog(user_id=current_user.id, insulin_units=form.insulin_units.data)
        db.session.add(log)
        db.session.commit()
        flash("Insulin dose logged successfully.", "success")
        return redirect(url_for('dashboard'))
    return render_template('log_insulin.html', form=form)


# Log meal route
@app.route('/log_meal', methods=['GET', 'POST'])
@login_required
def log_meal():
    """Log meals."""
    form = MealLogForm()
    if form.validate_on_submit():
        log = MealLog(user_id=current_user.id, carbs=form.carbs.data)
        db.session.add(log)
        db.session.commit()
        flash("Meal logged successfully.", "success")
        return redirect(url_for('dashboard'))
    return render_template('log_meal.html', form=form)


# Export logs to PDF
@app.route('/export_pdf')
@login_required
def export_pdf():
    """Export glucose logs to PDF."""
    try:
        logs = GlucoseLog.query.filter_by(user_id=current_user.id).all()
        rendered = render_template('export_pdf.html', logs=logs, current_time=datetime.now())
        pdf = BytesIO()
        pisa_status = pisa.CreatePDF(rendered, dest=pdf)
        if pisa_status.err:
            raise Exception("PDF generation error")

        response = make_response(pdf.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'inline; filename=glucose_logs.pdf'
        return response
    except Exception as e:
        logging.error(f"Error generating PDF: {e}")
        flash('Failed to generate PDF.', 'danger')
        return redirect(url_for('dashboard'))


# Logout route
@app.route('/logout')
@login_required
def logout():
    """Log out the current user and redirect to the login page."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Main entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        logging.info("Database initialized.")
    app.run(debug=True)
