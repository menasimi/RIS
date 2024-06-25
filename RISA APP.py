from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from twilio.rest import Client
from werkzeug.security import generate_password_hash, check_password_hash
import random
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///eventnook.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
app.config['TWILIO_ACCOUNT_SID'] = 'your_twilio_account_sid'
app.config['TWILIO_AUTH_TOKEN'] = 'your_twilio_auth_token'
app.config['TWILIO_PHONE_NUMBER'] = 'your_twilio_phone_number'
app.config['UPLOAD_FOLDER'] = 'uploads/'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
twilio_client = Client(app.config['TWILIO_ACCOUNT_SID'], app.config['TWILIO_AUTH_TOKEN'])

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(50), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    phone_verified = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(150), nullable=False)
    surname = db.Column(db.String(150), nullable=False)
    dob = db.Column(db.String(50), nullable=False)
    college = db.Column(db.String(150), nullable=False)
    course = db.Column(db.String(150), nullable=False)
    semester = db.Column(db.String(50), nullable=False)
	country = db.Column(db.String(50), nullable=False)
    passport_path = db.Column(db.String(150), nullable=False)
    visa_path = db.Column(db.String(150), nullable=False)
    photo_path = db.Column(db.String(150), nullable=False)
    college_id_path = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    tickets = db.Column(db.Integer, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_otp():
    return str(random.randint(100000, 999999))

def send_email(to, subject, body):
    msg = Message(subject, sender='your_email@gmail.com', recipients=[to])
    msg.body = body
    mail.send(msg)

def send_sms(to, body):
    twilio_client.messages.create(body=body, from_=app.config['TWILIO_PHONE_NUMBER'], to=to)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = generate_password_hash(request.form.get('password'))
        email = request.form.get('email')
        phone = request.form.get('phone')
        name = request.form.get('name')
        surname = request.form.get('surname')
        dob = request.form.get('dob')
        college = request.form.get('college')
        course = request.form.get('course')
        semester = request.form.get('semester')
		country = request.form.get('country')

        passport = request.files['passport']
        visa = request.files['visa']
        photo = request.files['photo']
        college_id = request.files['college_id']

        passport_path = os.path.join(app.config['UPLOAD_FOLDER'], passport.filename)
        visa_path = os.path.join(app.config['UPLOAD_FOLDER'], visa.filename)
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
        college_id_path = os.path.join(app.config['UPLOAD_FOLDER'], college_id.filename)

        passport.save(passport_path)
        visa.save(visa_path)
        photo.save(photo_path)
        college_id.save(college_id_path)

        user = User(username=username, password=password, email=email, phone=phone, name=name, surname=surname,
                    dob=dob, college=college, course=course, semester=semester, country=country, passport_path=passport_path,
                    visa_path=visa_path, photo_path=photo_path, college_id_path=college_id_path)
        db.session.add(user)
        db.session.commit()

        email_otp = generate_otp()
        phone_otp = generate_otp()
        session['email_otp'] = email_otp
        session['phone_otp'] = phone_otp
        session['user_id'] = user.id

        send_email(email, 'Email Verification', f'Your OTP is: {email_otp}')
        send_sms(phone, f'Your OTP is: {phone_otp}')

        return redirect(url_for('verify'))

    return render_template('register.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        email_otp = request.form.get('email_otp')
        phone_otp = request.form.get('phone_otp')
        user_id = session.get('user_id')
        user = User.query.get(user_id)

        if email_otp == session.get('email_otp') and phone_otp == session.get('phone_otp'):
            user.email_verified = True
            user.phone_verified = True
            db.session.commit()
            session.pop('email_otp', None)
            session.pop('phone_otp', None)
            session.pop('user_id', None)
            flash('Verification successful', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP', 'danger')

    return render_template('verify.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            reset_token = generate_otp()
            session['reset_token'] = reset_token
            session['reset_user_id'] = user.id
            send_email(email, 'Password Reset', f'Your reset code is: {reset_token}')
            flash('A reset code has been sent to your email', 'info')
            return redirect(url_for('reset_password'))
        else:
            flash('Email not found', 'danger')

    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        reset_token = request.form.get('reset_token')
        new_password = request.form.get('new_password')
        if reset_token == session.get('reset_token'):
            user_id = session.get('reset_user_id')
            user = User.query.get(user_id)
            user.password = generate_password_hash(new_password)
            db.session.commit()
            session.pop('reset_token', None)
            session.pop('reset_user_id', None)
            flash('Password reset successful', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid reset token', 'danger')

    return render_template('reset_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.email_verified and user.phone_verified:
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Email or phone not verified', 'danger')
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    events = Event.query.all()
    return render_template('dashboard.html', events=events)

@app.route('/profile')
@login_required
def profile():
    bookings = Booking.query.filter_by(user_id=current_user.id).all()
    events = [Event.query.get(booking.event_id) for booking in bookings]
    return render_template('profile.html', user=current_user, events=events)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    events = Event.query.all()
    return render_template('admin.html', users=users, events=events)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/events')
@login_required
def admin_events():
    if not current_user.is_admin:
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('dashboard'))
    events = Event.query.all()
    return render_template('admin_events.html', events=events)

@app.route('/admin/user/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('dashboard'))
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/event/delete/<int:event_id>')
@login_required
def delete_event(event_id):
    if not current_user.is_admin:
        flash('You do not have access to this page', 'danger')
        return redirect(url_for('dashboard'))
    event = Event.query.get(event_id)
    db.session.delete(event)
    db.session.commit()
    flash('Event deleted successfully', 'success')
    return redirect(url_for('admin_events'))

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        name = request.form.get('name')
        date = request.form.get('date')
        location = request.form.get('location')
        description = request.form.get('description')
        event = Event(name=name, date=date, location=location, description=description)
        db.session.add(event)
        db.session.commit()
        flash('Event created successfully', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_event.html')

@app.route('/book_event/<int:event_id>', methods=['GET', 'POST'])
@login_required
def book_event(event_id):
    event = Event.query.get(event_id)
    if request.method == 'POST':
        tickets = request.form.get('tickets')
        booking = Booking(user_id=current_user.id, event_id=event.id, tickets=tickets)
        db.session.add(booking)
        db.session.commit()
        flash('Booking successful', 'success')
        return redirect(url_for('dashboard'))
    return render_template('book_event.html', event=event)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
