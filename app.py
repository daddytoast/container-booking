from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError


app = Flask(__name__)
app.config['SECRET_KEY'] = 'qwerty312'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bookings.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Модель для бронирования
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    container_type = db.Column(db.String(50), nullable=False)
    size = db.Column(db.String(50), nullable=False)


# Формы
class RegistrationForm(FlaskForm):
    email = StringField('Email', [
        DataRequired(message="Email is required"),
        Email(message="Invalid email address")
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3)])
    confirmPassword = PasswordField('confirmPassword', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already in use. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# Маршруты
@app.route('/index.html')
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        new_user = User(email=form.email.data, password=hashed_password)

        db.session.add(new_user)

        db.session.commit()

        flash('Account created! You can now login.', 'success')

        return redirect(url_for('index'))
    return render_template('registration.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check your email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index.html'))


@app.route('/books')
def books():
    return render_template('application_form.html')

@app.route('/book', methods=['POST'])
def book():

    data = request.get_json()
    new_booking = Booking(
        name=data['name'],
        email=data['email'],
        container_type=data['container_type'],
        size=data['size']
    )
    db.session.add(new_booking)
    db.session.commit()

    return jsonify({"message": "Booking successful!"}), 201

@app.route('/bookings', methods=['GET'])
def get_bookings():
    bookings = Booking.query.all()
    output = []
    for booking in bookings:
        booking_data = {
            'id': booking.id,
            'name': booking.name,
            'email': booking.email,
            'container_type': booking.container_type,
            'size': booking.size
        }
        output.append(booking_data)
    return jsonify(output)

@app.route('/collection')
def collection():
    return render_template('collection.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
