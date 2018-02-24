import datetime
from flask import Flask, render_template, redirect, url_for, Session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, FloatField, DateField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import Flask
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired


app = Flask(__name__)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'njorogealexw@gmail.com'
app.config['MAIL_PASSWORD'] = 'alex2019'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///loginsystem.sqlite3'
app.config['SECRET_KEY']="alex"
app.config.update(dict(
    SECRET_KEY="wedferrstddndhge",
    WTF_CSRF_SECRET_KEY="alex"
))

Bootstrap(app)
mail=Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

'''Database classes'''
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    businesses = db.relationship('Business', backref='user', lazy=True)

class Business(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    business_name = db.Column(db.String(80))
    business_type = db.Column(db.String(80))
    business_location = db.Column(db.String(80))
    business_email = db.Column(db.String(50))
    business_owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    records = db.relationship('BusinessRecords', backref='business', lazy=True)

class BusinessRecords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    revenue = db.Column(db.Integer)
    expenditure = db.Column(db.Integer)
    profit = db.Column(db.Integer)
    date = db.Column(db.String(30))
    business_id = db.Column(db.Integer, db.ForeignKey('business.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

'''Web forms'''
class LoginForm(FlaskForm):
    username = StringField( validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "username"})
    password = PasswordField( validators=[InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "password"})
    remember = BooleanField("Remember me")


class RegisterForm(FlaskForm):
    email = StringField( validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)], render_kw={"placeholder": "email address"})
    username = StringField( validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "username"})
    password = PasswordField( validators=[InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "password"})


class ForgotPasswordForm(FlaskForm):
    email = StringField( validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)], render_kw={"placeholder": "email address"})


BUSINESS_TYPES = ('Department store', 'Merchandise', 'Discount stores', 'Supermarket', 'Warehouse Stores',
                  'Small shop', 'Speciality store', 'Mall', 'E Tailers', 'Jewellery store', 'Chemist shop',
                  'Delivery service')

class SetupBusinessForm(FlaskForm):
    business_name = StringField('Business Name', validators=[InputRequired(), Length(max=80)], render_kw={"placeholder": "business name"})
    business_type = SelectField(label='Business Type', choices=[(state, state) for state in BUSINESS_TYPES], render_kw={"placeholder": "business type"})
    business_location = StringField('Business Location', validators=[InputRequired(), Length(max=80)], render_kw={"placeholder": "business location"})
    business_email = StringField('Business Email', validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)], render_kw={"placeholder": "business email"})


class ChangePassword(FlaskForm):
    new_password = PasswordField('New Password',validators=[InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "new password"})
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), Length(min=8, max=80)], render_kw={"placeholder": "confirm password"})


class InsertRecordsForm(FlaskForm):
    revenue = FloatField('Total Revenue')
    expenditure = FloatField('Total Expenditure')


'''Routines'''
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        flash(u'Incorrect username or password!', 'error')
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(email=form.email.data, username = form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('setup'))
    return render_template('signup.html', form=form)


@app.route('/setup', methods=['GET', 'POST'])
@login_required
def setup():
    form = SetupBusinessForm()

    if form.validate_on_submit():
        new_business = Business(business_name=form.business_name.data, business_type=form.business_type.data,
                                business_email=form.business_email.data, business_owner_id=current_user.id,
                                business_location=form.business_location.data)
        db.session.add(new_business)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('setup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    form = InsertRecordsForm()
    date_ = datetime.date.today()
    return render_template('dashboard.html', results=BusinessRecords.query.filter_by(date = date_).first(), form=form, name=current_user.username, business =
                           Business.query.filter_by(business_owner_id=current_user.id).first())


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

s = URLSafeTimedSerializer('Thisisasecret!')

@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email_address = form.email.data
        token = s.dumps(email_address, salt='email-confirm')
        msg = Message('Reset Password', sender = 'njorogealexw@gmail.com', recipients = [email_address])
        link = url_for('change_password', token=token, _external=True)
        msg.body = "To change your password follow the link below {}".format(link)
        mail.send(msg)
    return render_template('forgotpassword.html', form=form)


@app.route('/change_password/<token>', methods = ['POST', 'GET'])
def change_password(token):
    email_ = s.loads(token, salt='email-confirm', max_age=600)
    form = ChangePassword()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.new_password.data, method='sha256')
        user = User.query.filter_by(email=email_).first()
        user.password = hashed_password
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('changepassword.html', form=form)


@app.route('/insertrecords', methods = ['POST', 'GET'])
def insertrecords():
    form = InsertRecordsForm()
    if form.validate_on_submit():
        revenue_ = form.revenue.data
        expenditure_ = form.expenditure.data
        profit_ = revenue_ - expenditure_
        date_ = datetime.date.today()
        if BusinessRecords.query.filter_by(date = date_).first() != date_:
            record = BusinessRecords(revenue=revenue_, expenditure=expenditure_,
                                 date=date_, profit=profit_)
            db.session.add(record)
            db.session.commit()
        return render_template('dashboard.html', results=BusinessRecords.query.filter_by(date = date_).first(),form=form, name=current_user.username, business =
                               Business.query.filter_by(business_owner_id=current_user.id).first())
    return render_template('dashboard.html', results=BusinessRecords.query.filter_by(date = date_).first(), form=form, name=current_user.username, business =
                           Business.query.filter_by(business_owner_id=current_user.id).first())



if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
