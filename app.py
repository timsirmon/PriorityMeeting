# app.py
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from models import db, User, Topic
from forms import RegistrationForm, LoginForm
from datetime import datetime
import os

app = Flask(__name__)

# Get absolute path for database
base_dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(base_dir, 'topics.db')

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key')

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    topics = Topic.query.order_by(Topic.votes.desc(), Topic.created_at.desc()).all()
    return render_template('index.html', topics=topics)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Logged in successfully!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/propose', methods=['GET', 'POST'])
@login_required
def propose():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        
        if not title:
            flash('Title is required!', 'error')
            return redirect(url_for('propose'))
            
        existing_topic = Topic.query.filter_by(title=title).first()
        if existing_topic:
            flash('A topic with this title already exists.', 'error')
            return redirect(url_for('propose'))
            
        topic = Topic(
            title=title,
            description=description,
            user_id=current_user.id
        )
        
        db.session.add(topic)
        db.session.commit()
        
        flash('Topic proposed successfully!', 'success')
        return redirect(url_for('index'))
        
    return render_template('propose.html')

@app.route('/vote/<int:topic_id>', methods=['POST'])
@login_required
def vote(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    vote_type = request.form.get('vote')
    
    if vote_type == 'upvote':
        topic.votes += 1
    elif vote_type == 'downvote' and topic.votes > 0:
        topic.votes -= 1
        
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/agenda')
@login_required
def agenda():
    topics = Topic.query.order_by(Topic.votes.desc(), Topic.created_at.desc()).all()
    return render_template('agenda.html', topics=topics)

if __name__ == '__main__':
    app.run(debug=True)