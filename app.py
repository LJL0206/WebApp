from flask import Flask, get_flashed_messages, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Required for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Student Model
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Float, nullable=False)

# Registration Form
class RegistrationForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Register')

# Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Login')

# Route to the login/registration page
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        return redirect(url_for('register'))  # Redirect to register if form is submitted
    return redirect(url_for('login'))  # Default to login page

# Route to register a new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            error = "Username already exists! Please choose a different one."
        else:
            hashed_password = generate_password_hash(password, method='scrypt')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))

    return render_template('register.html', error=error)



# Route to login a user
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    # Clear previous flash messages on login page load
    get_flashed_messages()  # This clears any existing flash messages
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id  # Store user id in session
            flash('Login successful!', 'success')
            return redirect(url_for('index'))  # Redirect to student management page
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)


# Route to display all students (Read)
@app.route('/students')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    students = Student.query.all()
    return render_template('index.html', students=students)

# Route to add a new student
@app.route('/add', methods=['GET', 'POST'])
def add_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        score = request.form['score']
        new_student = Student(student_id=student_id, name=name, score=float(score))
        db.session.add(new_student)
        db.session.commit()
        flash('Student added successfully!', 'success')
        return redirect(url_for('index'))  # Redirect to students list after adding

    return render_template('add_student.html')

# Route to edit an existing student
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_student(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    student = Student.query.get_or_404(id)
    
    if request.method == 'POST':
        student.student_id = request.form['student_id']
        student.name = request.form['name']
        student.score = request.form['score']
        db.session.commit()
        flash('Student updated successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit_student.html', student=student)

# Route to delete a student
@app.route('/delete/<int:id>', methods=['POST'])
def delete_student(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    student = Student.query.get_or_404(id)
    db.session.delete(student)
    db.session.commit()
    flash('Student deleted successfully!', 'success')
    return redirect(url_for('index'))

# Route to logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # Remove user id from session
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))  # Redirect to login after logout

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create all tables
    app.run(debug=True)