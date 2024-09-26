from flask_wtf.form import FlaskForm
from flask_wtf.file import FileAllowed, FileSize
from flask_datepicker import datepicker
from wtforms.validators import URL
from wtforms.fields import (
    StringField,
    PasswordField,
    EmailField,
    SubmitField,
    BooleanField,
    TextAreaField,
    SelectField,
    DateField,
    FileField,
    RadioField,
    TimeField
)
from wtforms.validators import (
    DataRequired,
    InputRequired,
    Length,
    Email
)
from datetime import date
from accounts.validators import (
    Unique,
    StrongNames,
    StrongPhone,
    StrongPassword
)
from accounts.models import User


class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        DataRequired(),
        Length(min=3, max=50),
        StrongNames()
    ])
    
    last_name = StringField('Last Name', validators=[
        DataRequired(),
        Length(min=3, max=50),
        StrongNames()
    ])
    
    date_of_birth = DateField('Date of Birth', format='%Y-%m-%d', validators=[DataRequired()])
    
    
    email = EmailField('Email', validators=[
        DataRequired(),
        Email(),
        Length(min=8, max=120),
        Unique(User, User.email, message='Email address already registered with us.')
    ])
    
    gender = SelectField('Gender', choices=[('male', 'Male'), ('female', 'Female')], default='male', validators=[DataRequired()])
    occupation = StringField('Occupation', validators=[DataRequired(), Length(min=5, max=50)])
    contact_number = StringField('Phone Number', validators=[DataRequired(), Length(min=10, max=15), StrongPhone()])
    address = TextAreaField('Address', validators=[Length(min=5, max=120)], render_kw={'rows': 1})
    postal_code = StringField('Postal Code', validators=[DataRequired(), Length(min=4, max=4)])
    role = SelectField('Role', choices=[('admin', 'Admin'), ('volunteer', 'Volunteer'), ('student', 'Student')], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), StrongPassword(), Length(min=8, max=20)])
    
    remember = BooleanField('I agree to the terms and conditions', validators=[DataRequired()])
    submit = SubmitField('Continue')
    
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email(), Length(min=8, max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')
    
class ForgotPasswordForm(FlaskForm):

    email = EmailField('Email Address',
                       validators=[DataRequired(), Length(8, 150), Email()]
                       )
    remember = BooleanField(
        'I agree & accept all terms of services.', validators=[DataRequired()])
    submit = SubmitField('Send Reset Link')


class ResetPasswordForm(FlaskForm):

    password = PasswordField('Password',
                             validators=[DataRequired(), Length(
                                 8, 20), StrongPassword()]
                             )
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), Length(
                                         8, 20), StrongPassword()]
                                     )
    remember = BooleanField('Remember me', validators=[DataRequired()])
    submit = SubmitField('Submit')


class ChangePasswordForm(FlaskForm):

    old_password = PasswordField('Old Password', validators=[
                                 DataRequired(), Length(8, 20)])
    new_password = PasswordField('New Password', validators=[
                                 DataRequired(), Length(8, 20)])
    confirm_password = PasswordField('Confirm New Password', validators=[
                                     DataRequired(), Length(8, 20)])
    remember = BooleanField('Remember me', validators=[DataRequired()])
    submit = SubmitField('Submit')
    
class EditUserProfileForm(FlaskForm):

    first_name = StringField('First Name', validators=[
                             DataRequired(), Length(3, 25), StrongNames()])
    last_name = StringField('Last Name', validators=[
                            DataRequired(), Length(3, 25), StrongNames()])
    profile_image = FileField('Profile Image',
                              validators=[
                                  FileAllowed(['jpg', 'jpeg', 'png', 'svg'],
                                              'Please upload images only.'),
                                  FileSize(max_size=2000000,
                                           message='Profile image size should not greater than 2MB.')
                              ]
                              )
    contact_number = StringField('Phone Number', validators=[Length(10, 10), StrongPhone()])
    occupation = StringField('Occupation', validators=[Length(5, 50)])
    address = TextAreaField('Address', validators=[Length(5, 120)], render_kw={'rows': 1})
    postal_code = StringField('Postal Code', validators=[Length(4, 4)])
    about = TextAreaField('About')
    submit = SubmitField('Save Profile')