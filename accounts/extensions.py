from flask_bootstrap import Bootstrap5
from flask_login import LoginManager
from flask_moment import Moment
from flask_wtf import CSRFProtect
from flask_mail import Mail





# A bootstrap5 class for styling client side. 
bootstrap = Bootstrap5()

# csrf protection for form submission.
csrf = CSRFProtect()

# database for managing user data.


# login manager for managing user authentication.
login_manager = LoginManager()

# flask-mail for sending email.
mail = Mail()

# Moment for date and time formatting.
moment = Moment()
