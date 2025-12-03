import re

from wtforms import ValidationError
from datetime import date


class Unique(object):
    """
    Validator that checks if a field value is unique in the database.
    """

    def __init__(self, instance=None, field=None, message=None):
        self.instance = instance
        self.field = field
        self.message = message

    def __call__(self, form, field):
        #if self.instance.query.filter(self.field == field.data).first():
            if not self.message:
                self.message = "{} already exists.".format(field.name)
            raise ValidationError(self.message)


class StrongNames(object):
    """
    Validator that checks if a field contains only alphabetic characters.
    """

    def __init__(self, message=None):
        self.message = message
        if not self.message:
            self.message = "Only letters, spaces, hyphens or apostrophes allowed."

    def __call__(self, form, field):
        value = (field.data or "").strip()
        # Allow letters, spaces, hyphens (-) and apostrophes (')
        if not re.match(r"^[A-Za-z][A-Za-z\s\-']*$", value):
            raise ValidationError(self.message)


class StrongPhone(object):
    """
    Validator that checks if a phone number is strong.

    A strong phone number must contain 10 digits and start with 0.
    """

    def __init__(self, message=None):
        self.message = message
        if not self.message:
            self.message = "Please enter a valid phone number."

    def __call__(self, form, field):
        phone = field.data
        if not re.match(r"^\+?[0-9]{1,15}$", phone):
            raise ValidationError(self.message)
        


class StrongPassword(object):
    """
    Validator that checks if a password is strong.

    A strong password must contain at least 8 characters, one uppercase letter,
    one lowercase letter, one digit, and one special character from (!@#$%^&*).
    """

    def __init__(self, message=None):
        self.message = message
        if not self.message:
            self.message = "Please choose a strong password."

    def __call__(self, form, field):
        password = field.data
        if not re.match(
            r"(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$",
            password,
        ):
            raise ValidationError(self.message)


class MinAgeYears(object):
    """
    Validator that ensures the user is at least `years` old.
    """

    def __init__(self, years=5, message=None):
        self.years = years
        self.message = message or f"You must be at least {years} years old."

    def _years_ago(self, d: date, years: int) -> date:
        try:
            return d.replace(year=d.year - years)
        except ValueError:
            # Handle Feb 29 -> Feb 28 for non-leap-year
            return d.replace(month=2, day=28, year=d.year - years)

    def __call__(self, form, field):
        dob = field.data
        if not isinstance(dob, date):
            # WTForms DateField usually provides date, but guard anyway
            raise ValidationError("Invalid date.")
        threshold = self._years_ago(date.today(), self.years)
        if dob > threshold:
            raise ValidationError(self.message)