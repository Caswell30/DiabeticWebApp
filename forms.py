from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField
from wtforms.validators import DataRequired, Email, Length, EqualTo, NumberRange

# Registration form for new users
class RegistrationForm(FlaskForm):
    email = StringField(
        'Email', 
        validators=[
            DataRequired(),  # Field is required
            Email()  # Validates proper email format
        ]
    )
    password = PasswordField(
        'Password', 
        validators=[
            DataRequired(),  # Field is required
            Length(min=8)  # Password must be at least 8 characters long
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password', 
        validators=[
            DataRequired(),  # Field is required
            EqualTo('password')  # Ensures passwords match
        ]
    )
    submit = SubmitField('Register')  # Submit button

# Login form for existing users
class LoginForm(FlaskForm):
    email = StringField(
        'Email', 
        validators=[
            DataRequired(),  # Field is required
            Email()  # Validates proper email format
        ]
    )
    password = PasswordField(
        'Password', 
        validators=[
            DataRequired()  # Field is required
        ]
    )
    submit = SubmitField('Login')  # Submit button

# Form for logging blood glucose levels
class GlucoseLogForm(FlaskForm):
    glucose_level = FloatField(
        'Blood Glucose Level (mg/dL)', 
        validators=[
            DataRequired(),  # Field is required
            NumberRange(min=0.1, max=35.0)  # Validates the range of acceptable values
        ]
    )
    submit = SubmitField('Log Glucose')  # Submit button

# Form for logging insulin doses
class InsulinLogForm(FlaskForm):
    insulin_units = FloatField(
        'Insulin Dose (units)', 
        validators=[
            DataRequired(),  # Field is required
            NumberRange(min=0, max=100)  # Validates the range of acceptable values
        ]
    )
    submit = SubmitField('Log Insulin')  # Submit button

# Form for logging meal carbohydrates
class MealLogForm(FlaskForm):
    carbs = FloatField(
        'Carbohydrates (g)', 
        validators=[
            DataRequired(),  # Field is required
            NumberRange(min=0, max=300)  # Validates the range of acceptable values
        ]
    )
    submit = SubmitField('Log Meal')  # Submit button

# Form for user settings (e.g., insulin-to-carb ratio, target glucose levels)
class UserSettingsForm(FlaskForm):
    insulin_to_carb_ratio = FloatField(
        'Insulin to Carb Ratio',
        validators=[
            DataRequired(message="Insulin-to-carb ratio is required."),  # Field is required with a custom error message
            NumberRange(
                min=0.1, 
                max=100, 
                message="Please enter a valid ratio."  # Custom error message for out-of-range values
            )
        ]
    )
    target_glucose = FloatField(
        'Target Glucose Level (mg/dL)',
        validators=[
            DataRequired(message="Target glucose level is required."),  # Field is required with a custom error message
            NumberRange(
                min=50, 
                max=300, 
                message="Please enter a valid glucose level."  # Custom error message for out-of-range values
            )
        ]
    )
    submit = SubmitField('Save Changes')  # Submit button
