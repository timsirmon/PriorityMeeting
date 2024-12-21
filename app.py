# app.py
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer

from utils.email import send_password_reset_email, mail
load_dotenv()

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_mail import Mail, Message
from models import db, User, Topic, VoteRecord
from forms import RegistrationForm, LoginForm
from datetime import datetime
import os
import logging
from logging.handlers import RotatingFileHandler
from forms import ResetPasswordRequestForm, ResetPasswordForm

app = Flask(__name__)
mail.init_app(app)

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
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # or your SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)


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
        app.logger.error('Reset password error:', exc_info=True)  # Add this in the exception handlers


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Updated from User.query.get()
# @app.route('/')
# def index():
    # return render_template('coming_soon.html')

# @app.route('/dev')
# def development():  
    # try:
    #     topics = Topic.query.order_by(Topic.votes.desc(), Topic.created_at.desc()).all()
    #     return render_template('index.html', topics=topics)
    # except Exception as e:
    #     app.logger.error(f'Error in index route: {str(e)}')
    #     flash('An error occurred while loading topics.', 'error')
    #     return render_template('index.html', topics=[])
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return render_template('index.html')
    try:
        sort = request.args.get('sort')
        direction = request.args.get('direction', 'asc')  # default to ascending
        query = Topic.query.filter_by(completed=False)

        if sort == 'title':
            query = query.order_by(Topic.title.desc() if direction == 'desc' else Topic.title)
        elif sort == 'votes':
            query = query.order_by(Topic.votes.desc() if direction == 'desc' else Topic.votes)
        elif sort == 'date':
            query = query.order_by(Topic.created_at if direction == 'desc' else Topic.created_at.desc())
        else:
            # Default sort by creation date, newest first
            query = query.order_by(Topic.created_at.desc())

        topics = query.all()
        
        # Add these lines to pass the required variables
        votes_used = current_user.get_total_votes_used()
        total_votes = current_user.get_total_available_votes()
        
        return render_template('index.html', 
                             topics=topics,
                             current_sort=sort, 
                             current_direction=direction,
                             votes_used=votes_used,
                             total_votes=total_votes)
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

        # Get all vote records for this topic before deleting
        vote_records = VoteRecord.query.filter_by(topic_id=topic_id).all()

        # Delete all vote records for this topic
        for vote_record in vote_records:
            db.session.delete(vote_record)

        # Delete the topic
        db.session.delete(topic)
        db.session.commit()

        # Notify user about vote return
        if vote_records:
            flash(f'Topic deleted successfully. {len(vote_records)} votes have been returned to users.', 'success')
        else:
            flash('Topic deleted successfully.', 'success')

    except Exception as e:
        db.session.rollback()
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
        
        votes_used = current_user.get_total_votes_used()
        total_available = current_user.get_total_available_votes()
        
        if vote_type == 'upvote':
            if votes_used < total_available:
                topic.votes += 1
                vote_record = VoteRecord(
                    user_id=current_user.id,
                    topic_id=topic_id
                )
                db.session.add(vote_record)
                db.session.commit()
                flash('Vote added!', 'success')
            else:
                flash(f'You have used all {total_available} of your votes.', 'error')
        
        elif vote_type == 'downvote':
            # Check if user has voted on this topic
            vote_record = VoteRecord.query.filter_by(
                user_id=current_user.id,
                topic_id=topic_id
            ).first()
            
            if vote_record:
                db.session.delete(vote_record)
                topic.votes -= 1
                db.session.commit()
                flash('Vote removed and is now available to use again!', 'success')
            else:
                flash('You can only remove votes from topics you\'ve voted on.', 'error')
                
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

@app.route('/complete_topic/<int:topic_id>', methods=['POST'])
@login_required
def complete_topic(topic_id):
    try:
        topic = Topic.query.get_or_404(topic_id)
        topic.completed = True
        topic.completed_at = datetime.utcnow()
        db.session.commit()
        flash('Topic marked as completed!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error completing topic: {str(e)}')
        flash('An error occurred while completing the topic.', 'error')
    return redirect(url_for('index'))

@app.route('/reactivate_topic/<int:topic_id>', methods=['POST'])
@login_required
def reactivate_topic(topic_id):
    try:
        topic = Topic.query.get_or_404(topic_id)
        topic.completed = False
        topic.completed_at = None
        db.session.commit()
        flash('Topic reactivated!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error reactivating topic: {str(e)}')
        flash('An error occurred while reactivating the topic.', 'error')
    return redirect(url_for('completed_topics'))

@app.route('/completed')
@login_required
def completed_topics():
    try:
        topics = Topic.query.filter_by(completed=True).order_by(Topic.completed_at.desc()).all()
        return render_template('completed.html', topics=topics)
    except Exception as e:
        app.logger.error(f'Error loading completed topics: {str(e)}')
        flash('An error occurred while loading completed topics.', 'error')
        return render_template('completed.html', topics=[])

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for instructions to reset your password', 'info')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', form=form)

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    try:
        form = ResetPasswordRequestForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                try:
                    send_password_reset_email(user)
                    app.logger.info(f'Password reset email sent to {user.email}')
                except Exception as e:
                    app.logger.error(f'Failed to send password reset email: {str(e)}', exc_info=True)
                    flash('Error sending password reset email.', 'error')
                    return render_template('reset_password_request.html', form=form)
            flash('Check your email for instructions to reset your password', 'info')
            return redirect(url_for('login'))
        return render_template('reset_password_request.html', form=form)
    except Exception as e:
        app.logger.error(f'Reset password request error: {str(e)}', exc_info=True)
        flash('An unexpected error occurred.', 'error')
        return render_template('reset_password_request.html', form=form)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = URLSafeTimedSerializer(app.config['SECRET_KEY'])\
            .loads(token, salt='email-confirm-salt', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            user.email_confirmed = True
            user.email_confirm_date = datetime.utcnow()
            db.session.commit()
            flash('Email confirmed successfully!', 'success')
        else:
            flash('Invalid confirmation link', 'error')
    except:
        flash('The confirmation link is invalid or has expired', 'error')
    return redirect(url_for('login'))

# Create a test route temporarily
@app.route('/test_email')
def test_email():
    try:
        msg = Message('Test Email',
                     sender=app.config['MAIL_DEFAULT_SENDER'],
                     recipients=['timsirmon@gmail.com'])
        msg.body = 'This is a test email'
        mail.send(msg)
        return 'Mail sent!'
    except Exception as e:
        return f'Error: {str(e)}'
    
if __name__ == '__main__':
    app.run(debug=True)
