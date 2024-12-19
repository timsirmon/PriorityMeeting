# app.py
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from models import db, User, Topic
from forms import RegistrationForm, LoginForm
from datetime import datetime
import os
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# Configure logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.DEBUG)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.DEBUG)
app.logger.info('PriorityMeeting startup')

# Get absolute path for database
base_dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(base_dir, 'topics.db')
app.logger.info(f'Database path: {db_path}')

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key')

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'error'

# Ensure database tables exist
with app.app_context():
    try:
        db.create_all()
        app.logger.info('Database tables created successfully')
    except Exception as e:
        app.logger.error(f'Error creating database tables: {str(e)}')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('coming_soon.html')

@app.route('/dev')
def index():
    try:
        topics = Topic.query.order_by(Topic.votes.desc(), Topic.created_at.desc()).all()
        return render_template('index.html', topics=topics)
    except Exception as e:
        app.logger.error(f'Error in index route: {str(e)}')
        flash('An error occurred while loading topics.', 'error')
        return render_template('index.html', topics=[])

@app.route('/delete_topic/<int:topic_id>', methods=['POST'])
@login_required
def delete_topic(topic_id):
    try:
        topic = Topic.query.get_or_404(topic_id)
        
        # Check if current user is the topic creator
        if topic.user_id != current_user.id:
            flash('You can only delete your own topics.', 'error')
            return redirect(url_for('index'))
            
        db.session.delete(topic)
        db.session.commit()
        flash('Topic deleted successfully.', 'success')
    except Exception as e:
        app.logger.error(f'Error deleting topic: {str(e)}')
        flash('An error occurred while deleting the topic.', 'error')
        
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    try:
        if form.validate_on_submit():
            app.logger.debug('Form submitted and validated')
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_password
            )
            app.logger.debug(f'Created user object: {user.username}, {user.email}')
            
            try:
                db.session.add(user)
                db.session.commit()
                app.logger.info(f'Successfully registered user: {user.username}')
                flash('Your account has been created! You can now log in.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                app.logger.error(f'Database error during registration: {str(e)}')
                flash('An error occurred while creating your account. Please try again.', 'error')
                return render_template('register.html', form=form)
    except Exception as e:
        app.logger.error(f'Error in register route: {str(e)}')
        flash('An error occurred during registration. Please try again.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    try:
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                flash('Logged in successfully!', 'success')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Login unsuccessful. Please check email and password.', 'error')
    except Exception as e:
        app.logger.error(f'Error in login route: {str(e)}')
        flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    try:
        logout_user()
        flash('You have been logged out.', 'success')
    except Exception as e:
        app.logger.error(f'Error in logout route: {str(e)}')
        flash('An error occurred during logout.', 'error')
    return redirect(url_for('index'))

@app.route('/propose', methods=['GET', 'POST'])
@login_required
def propose():
    if request.method == 'POST':
        try:
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
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error in propose route: {str(e)}')
            flash('An error occurred while proposing the topic.', 'error')
            return redirect(url_for('propose'))
            
    return render_template('propose.html')

@app.route('/vote/<int:topic_id>', methods=['POST'])
@login_required
def vote(topic_id):
    try:
        topic = Topic.query.get_or_404(topic_id)
        vote_type = request.form.get('vote')
        
        if vote_type == 'upvote':
            topic.votes += 1
        elif vote_type == 'downvote' and topic.votes > 0:
            topic.votes -= 1
            
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error in vote route: {str(e)}')
        flash('An error occurred while voting.', 'error')
    return redirect(url_for('index'))

@app.route('/agenda')
@login_required
def agenda():
    try:
        topics = Topic.query.order_by(Topic.votes.desc(), Topic.created_at.desc()).all()
        return render_template('agenda.html', topics=topics)
    except Exception as e:
        app.logger.error(f'Error in agenda route: {str(e)}')
        flash('An error occurred while loading the agenda.', 'error')
        return render_template('agenda.html', topics=[])

# Add error handlers
@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'Page not found: {request.url}')
    return render_template('error.html', message='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {str(error)}')
    return render_template('error.html', message='Internal server error'), 500

if __name__ == '__main__':
    app.run(debug=True)