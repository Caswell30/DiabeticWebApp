from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

# Initialize the database
db = SQLAlchemy()

class User(UserMixin, db.Model):
    """Model for users with authentication and settings."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    insulin_to_carb_ratio = db.Column(db.Float, nullable=False, default=10.0)
    target_glucose = db.Column(db.Integer, nullable=False, default=100)

    def set_password(self, password):
        """Hashes and sets the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Validates the provided password."""
        return check_password_hash(self.password_hash, password)

class GlucoseLog(db.Model):
    """Model for logging blood glucose readings."""
    __tablename__ = 'glucose_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    glucose_level = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class MealLog(db.Model):
    """Model for logging meal carbohydrate intake."""
    __tablename__ = 'meal_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    carbs = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class InsulinLog(db.Model):
    """Model for logging insulin doses."""
    __tablename__ = 'insulin_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    insulin_units = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
