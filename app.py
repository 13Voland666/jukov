from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
import os
from wtforms import StringField, PasswordField, SubmitField, ValidationError

# Кастомный валидатор для проверки совпадения паролей
def passwords_match(form, field):
    if form.password.data != form.confirm_password.data:
        raise ValidationError('Passwords must match')
# Кастомный валидатор для проверки уникальности имени пользователя
def unique_username(form, field):
    if User.query.filter_by(username=field.data).first():
        raise ValidationError('This username is already taken. Please choose a different one.')


    
    
    
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Настройки базы данных
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Модель данных для пользователей
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    entries = db.relationship('Entry', backref='author', lazy=True)

# Модель данных для заметок
class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Создание таблиц
with app.app_context():
    db.create_all()

# Форма регистрации
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150), unique_username])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    

# Форма входа
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Главная страница
@app.route('/')
def home():
    register_form = RegistrationForm()
    login_form = LoginForm()
    return render_template('home.html', register_form=register_form, login_form=login_form)

# Маршрут для регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Проверка наличия пользователя с таким именем
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('This username is already taken. Please choose a different one.', 'danger')
            return render_template('home.html', register_form=form, login_form=LoginForm())
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        return redirect(url_for('index'))
    
    return render_template('home.html', register_form=form, login_form=LoginForm())

# Маршрут для входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password. Please try again.', 'danger')
    return render_template('home.html', register_form=RegistrationForm(), login_form=form)


# Маршрут для выхода
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

# Маршрут для главной страницы с заметками
@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    entries = Entry.query.filter_by(user_id=user.id).all()
    return render_template('index.html', entries=entries)

# Маршрут для добавления заметки
@app.route('/add', methods=['POST'])
def add_entry():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    title = request.form['title']
    content = request.form['content']
    user_id = session['user_id']
    new_entry = Entry(title=title, content=content, user_id=user_id)
    db.session.add(new_entry)
    db.session.commit()
    return redirect(url_for('index'))

# Маршрут для удаления заметки
@app.route('/delete/<int:entry_id>', methods=['POST'])
def delete_entry(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != session['user_id']:
        return redirect(url_for('index'))
    db.session.delete(entry)
    db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
