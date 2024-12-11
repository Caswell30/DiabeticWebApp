from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

# Initialize the database
db = SQLAlchemy()

class User(UserMixin, db.Model):
    """Model for storing user details and authentication information."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each user
    email = db.Column(db.String(120), unique=True, nullable=False)  # User email (must be unique)
    password_hash = db.Column(db.String(128))  # Hashed password for authentication
    insulin_to_carb_ratio = db.Column(db.Float, nullable=False, default=10.0)  # Ratio for meal calculations
    target_glucose = db.Column(db.Integer, nullable=False, default=100)  # User's target glucose level

    def set_password(self, password):
        """Hashes and sets the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Validates the provided password against the stored hash."""
        return check_password_hash(self.password_hash, password)

class GlucoseLog(db.Model):
    """Model for logging blood glucose readings."""
    __tablename__ = 'glucose_logs'
    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each glucose log
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Associated user ID
    glucose_level = db.Column(db.Float, nullable=False)  # Recorded blood glucose level (mg/dL)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())  # Timestamp of the log entry

class MealLog(db.Model):
    """Model for logging carbohydrate intake during meals."""
    __tablename__ = 'meal_logs'
    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each meal log
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Associated user ID
    carbs = db.Column(db.Float, nullable=False)  # Amount of carbohydrates consumed (grams)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())  # Timestamp of the log entry

class InsulinLog(db.Model):
    """Model for logging insulin doses."""
    __tablename__ = 'insulin_logs'
    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each insulin log
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Associated user ID
    insulin_units = db.Column(db.Float, nullable=False)  # Units of insulin administered
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())  # Timestamp of the log entry
