from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Настройки базы данных
basedir = os.path.abspath(os.path.dirname(__file__))

# Настройки базы данных PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:13666@localhost/New'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Настройки для загрузки изображений
UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
    image_path = db.Column(db.String(255))  # Путь к изображению
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Создание таблиц
with app.app_context():
    db.create_all()

# Форма регистрации
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# Форма входа
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Функция для проверки разрешённых расширений файлов
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            form.username.errors.append('This username is already taken. Please choose a different one.')
        else:
            user = User(username=form.username.data, password_hash=generate_password_hash(form.password.data))
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('home'))
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

# Маршрут для редактирования заметки
@app.route('/edit/<int:entry_id>', methods=['POST'])
def edit_entry(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != session['user_id']:
        return redirect(url_for('index'))
    if request.method == 'POST':
        entry.title = request.form['title']
        entry.content = request.form['content']
        db.session.commit()
        flash('Entry updated successfully!', 'success')
    return redirect(url_for('index'))

# Маршрут для добавления изображения к заметке
@app.route('/add_image/<int:entry_id>', methods=['POST'])
def add_image(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    entry = Entry.query.get_or_404(entry_id)
    if entry.user_id != session['user_id']:
        return redirect(url_for('index'))
    if 'image' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))
    file = request.files['image']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Изменяем путь сохранения на абсолютный, указывая полный путь к файлу
        file.save(os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], filename))
        entry.image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        db.session.commit()
        flash('Image uploaded successfully!', 'success')
    else:
        flash('Invalid file type. Allowed file types are png, jpg, jpeg, gif', 'danger')
    return redirect(url_for('index'))
print('Для запуска - http://127.0.0.1:5000/')
if __name__ == '__main__':
    app.run(debug=True)


