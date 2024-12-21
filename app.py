import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_mail import Mail, Message
from dotenv import load_dotenv

from models import db, User, Topic, VoteRecord  # Ensure VoteRecord is imported
from forms import (
    RegistrationForm,
    LoginForm,
    ResetPasswordRequestForm,
    ResetPasswordForm,
)
from utils.email import (
    send_email_confirmation,
    send_password_reset_email,
    mail,
)

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# 1. Configure Logging (Rotating logs in 'logs/app.log')
if not os.path.exists("logs"):
    os.mkdir("logs")

file_handler = RotatingFileHandler(
    "logs/app.log", maxBytes=10240, backupCount=10
)
file_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
    )
)
file_handler.setLevel(logging.DEBUG)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.DEBUG)
app.logger.info("PriorityMeeting startup")

# 2. Basic App Config (DB, Secret Key, Mail, etc.)
base_dir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(base_dir, "topics.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_key")

# Flask-Mail settings (ensure these are set in your .env)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER")

# 3. Initialize Extensions
mail.init_app(app)  # Initialize Mail AFTER setting app.config
db.init_app(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"

# Ensure database tables exist
# with app.app_context():
#     try:
#         db.create_all()
#         app.logger.info("Database tables created successfully")
#     except Exception as e:
#         app.logger.error(f"Error creating database tables: {str(e)}")
#         app.logger.error("Database creation error:", exc_info=True)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Updated from User.query.get()


# --------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------

@app.route("/")
def index():
    if not current_user.is_authenticated:
        return render_template("index.html")
    try:
        sort = request.args.get("sort")
        direction = request.args.get("direction", "asc")  # default to ascending
        query = Topic.query.filter_by(completed=False)

        if sort == "title":
            query = query.order_by(Topic.title.desc() if direction == "desc" else Topic.title)
        elif sort == "votes":
            query = query.order_by(Topic.votes.desc() if direction == "desc" else Topic.votes)
        elif sort == "date":
            query = query.order_by(Topic.created_at.desc() if direction == "desc" else Topic.created_at)
        else:
            # Default sort by creation date, newest first
            query = query.order_by(Topic.created_at.desc())

        topics = query.all()

        # Add these lines to pass the required variables
        votes_used = current_user.get_total_votes_used()
        total_votes = current_user.get_total_available_votes()

        return render_template(
            "index.html",
            topics=topics,
            current_sort=sort,
            current_direction=direction,
            votes_used=votes_used,
            total_votes=total_votes,
        )
    except Exception as e:
        app.logger.error(f"Error in index route: {str(e)}", exc_info=True)
        flash("An error occurred while loading topics.", "error")
        return render_template("index.html", topics=[])


@app.route("/delete_topic/<int:topic_id>", methods=["POST"])
@login_required
def delete_topic(topic_id):
    try:
        topic = Topic.query.get_or_404(topic_id)

        # Check if current user is the topic creator
        if topic.user_id != current_user.id:
            flash("You can only delete your own topics.", "error")
            return redirect(url_for("index"))

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
            flash(
                f"Topic deleted successfully. {len(vote_records)} votes have been returned to users.",
                "success",
            )
        else:
            flash("Topic deleted successfully.", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting topic: {str(e)}", exc_info=True)
        flash("An error occurred while deleting the topic.", "error")

    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = RegistrationForm()
    try:
        if form.validate_on_submit():
            try:
                app.logger.debug("Form submitted and validated")
                hashed_password = bcrypt.generate_password_hash(
                    form.password.data
                ).decode("utf-8")
                user = User(
                    username=form.username.data,
                    email=form.email.data,
                    password_hash=hashed_password,
                )
                app.logger.debug(f"Created user object: {user.username}, {user.email}")

                db.session.add(user)
                db.session.commit()
                app.logger.info(f"Successfully registered user: {user.username}")

                # Send confirmation email
                send_email_confirmation(user)
                flash(
                    "Your account has been created! Please check your email to confirm.",
                    "success",
                )
                return redirect(url_for("login"))
            except Exception as e:
                db.session.rollback()
                app.logger.error(
                    f"Database error during registration: {str(e)}", exc_info=True
                )
                flash(
                    "An error occurred while creating your account. Please try again.",
                    "error",
                )
                return render_template("register.html", form=form)
    except Exception as e:
        app.logger.error(f"Error in register route: {str(e)}", exc_info=True)
        flash("An error occurred during registration. Please try again.", "error")

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()
    try:
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
                if not user.email_confirmed:
                    flash(
                        "Please confirm your email address before logging in.",
                        "warning",
                    )
                    return redirect(url_for("login"))
                login_user(user, remember=form.remember.data)
                next_page = request.args.get("next")
                flash("Logged in successfully!", "success")
                return redirect(next_page) if next_page else redirect(url_for("index"))
            else:
                flash(
                    "Login unsuccessful. Please check email and password.", "error"
                )
    except Exception as e:
        app.logger.error(f"Error in login route: {str(e)}", exc_info=True)
        flash("An error occurred during login. Please try again.", "error")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    try:
        logout_user()
        flash("You have been logged out.", "success")
    except Exception as e:
        app.logger.error(f"Error in logout route: {str(e)}", exc_info=True)
        flash("An error occurred during logout.", "error")
    return redirect(url_for("index"))


@app.route("/propose", methods=["GET", "POST"])
@login_required
def propose():
    if request.method == "POST":
        try:
            title = request.form.get("title")
            description = request.form.get("description")

            if not title:
                flash("Title is required!", "error")
                return redirect(url_for("propose"))

            existing_topic = Topic.query.filter_by(title=title).first()
            if existing_topic:
                flash("A topic with this title already exists.", "error")
                return redirect(url_for("propose"))

            topic = Topic(
                title=title,
                description=description,
                user_id=current_user.id,
            )

            db.session.add(topic)
            db.session.commit()

            flash("Topic proposed successfully!", "success")
            return redirect(url_for("index"))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error in propose route: {str(e)}", exc_info=True)
            flash("An error occurred while proposing the topic.", "error")
            return redirect(url_for("propose"))

    return render_template("propose.html")


@app.route("/vote/<int:topic_id>", methods=["POST"])
@login_required
def vote(topic_id):
    try:
        topic = Topic.query.get_or_404(topic_id)
        vote_type = request.form.get("vote")

        votes_used = current_user.get_total_votes_used()
        total_available = current_user.get_total_available_votes()

        if vote_type == "upvote":
            if votes_used < total_available:
                topic.votes += 1
                vote_record = VoteRecord(
                    user_id=current_user.id, topic_id=topic_id
                )
                db.session.add(vote_record)
                db.session.commit()
                flash("Vote added!", "success")
            else:
                flash(f"You have used all {total_available} of your votes.", "error")

        elif vote_type == "downvote":
            # Check if user has voted on this topic
            vote_record = VoteRecord.query.filter_by(
                user_id=current_user.id, topic_id=topic_id
            ).first()

            if vote_record:
                db.session.delete(vote_record)
                topic.votes -= 1
                db.session.commit()
                flash(
                    "Vote removed and is now available to use again!", "success"
                )
            else:
                flash(
                    "You can only remove votes from topics you've voted on.", "error"
                )

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in vote route: {str(e)}", exc_info=True)
        flash("An error occurred while voting.", "error")

    return redirect(url_for("index"))


@app.route("/agenda")
@login_required
def agenda():
    try:
        topics = Topic.query.order_by(
            Topic.votes.desc(), Topic.created_at.desc()
        ).all()
        return render_template("agenda.html", topics=topics)
    except Exception as e:
        app.logger.error(f"Error in agenda route: {str(e)}", exc_info=True)
        flash("An error occurred while loading the agenda.", "error")
        return render_template("agenda.html", topics=[])


@app.route("/complete_topic/<int:topic_id>", methods=["POST"])
@login_required
def complete_topic(topic_id):
    try:
        topic = Topic.query.get_or_404(topic_id)
        topic.completed = True
        topic.completed_at = datetime.utcnow()
        db.session.commit()
        flash("Topic marked as completed!", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error completing topic: {str(e)}", exc_info=True)
        flash("An error occurred while completing the topic.", "error")
    return redirect(url_for("index"))


@app.route("/reactivate_topic/<int:topic_id>", methods=["POST"])
@login_required
def reactivate_topic(topic_id):
    try:
        topic = Topic.query.get_or_404(topic_id)
        topic.completed = False
        topic.completed_at = None
        db.session.commit()
        flash("Topic reactivated!", "success")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error reactivating topic: {str(e)}", exc_info=True)
        flash("An error occurred while reactivating the topic.", "error")
    return redirect(url_for("completed_topics"))


@app.route("/completed")
@login_required
def completed_topics():
    try:
        topics = Topic.query.filter_by(completed=True).order_by(
            Topic.completed_at.desc()
        ).all()
        return render_template("completed.html", topics=topics)
    except Exception as e:
        app.logger.error(f"Error loading completed topics: {str(e)}", exc_info=True)
        flash("An error occurred while loading completed topics.", "error")
        return render_template("completed.html", topics=[])
    

# --------------------------------------------------------------------
# Password Reset Routes
# --------------------------------------------------------------------

@app.route("/reset_password_request", methods=["GET", "POST"])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = ResetPasswordRequestForm()
    try:
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                try:
                    send_password_reset_email(user)
                    app.logger.info(
                        f"Password reset email sent to {user.email}"
                    )
                except Exception as e:
                    app.logger.error(
                        f"Failed to send password reset email: {str(e)}",
                        exc_info=True,
                    )
                    flash(
                        "Error sending password reset email.", "error"
                    )
                    return render_template(
                        "reset_password_request.html", form=form
                    )
            # To prevent email enumeration, always flash the same message
            flash(
                "Check your email for instructions to reset your password",
                "info",
            )
            return redirect(url_for("login"))
    except Exception as e:
        app.logger.error(
            f"Reset password request error: {str(e)}", exc_info=True
        )
        flash("An unexpected error occurred.", "error")

    return render_template("reset_password_request.html", form=form)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    user = User.verify_reset_token(token)
    if not user:
        flash("Invalid or expired reset token", "error")
        return redirect(url_for("login"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            app.logger.debug(
                f"Resetting password for user ID {user.id} ({user.email})"
            )
            user.password_hash = bcrypt.generate_password_hash(
                form.password.data
            ).decode("utf-8")
            db.session.commit()
            app.logger.info(
                f"Password reset successfully for user ID {user.id} ({user.email})"
            )
            flash("Your password has been reset", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            app.logger.error(
                f"Error resetting password for user ID {user.id}: {str(e)}",
                exc_info=True,
            )
            flash("An error occurred while resetting your password.", "error")
            return render_template("reset_password.html", form=form)

    return render_template("reset_password.html", form=form)


# --------------------------------------------------------------------
# Email Confirmation Route
# --------------------------------------------------------------------

@app.route("/confirm_email/<token>")
def confirm_email(token):
    try:
        email = User.verify_confirmation_token(token)
        if not email:
            flash("The confirmation link is invalid or has expired.", "error")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Invalid confirmation link.", "error")
            return redirect(url_for("login"))

        if user.email_confirmed:
            flash("Account already confirmed. Please log in.", "info")
        else:
            user.email_confirmed = True
            user.email_confirm_date = datetime.utcnow()
            db.session.commit()
            app.logger.info(f"Email confirmed for user {user.email}")
            flash("Email confirmed successfully!", "success")
    except Exception as e:
        app.logger.error(f"Error confirming email: {str(e)}", exc_info=True)
        flash("The confirmation link is invalid or has expired.", "error")
    return redirect(url_for("login"))


# --------------------------------------------------------------------
# Test Email Route (for debugging)
# --------------------------------------------------------------------

@app.route("/test_email")
def test_email():
    try:
        msg = Message(
            "Test Email",
            sender=app.config["MAIL_DEFAULT_SENDER"],
            recipients=["timsirmon@gmail.com"],
        )
        msg.body = "This is a test email"
        mail.send(msg)
        return "Mail sent!"
    except Exception as e:
        app.logger.error(f"Error sending test email: {str(e)}", exc_info=True)
        return f"Error: {str(e)}"


# --------------------------------------------------------------------
# Error Handlers
# --------------------------------------------------------------------

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f"Page not found: {request.url}")
    return render_template("error.html", message="Page not found"), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f"Server Error: {str(error)}", exc_info=True)
    return render_template("error.html", message="Internal server error"), 500


if __name__ == "__main__":
    # For local testing only; in production use Gunicorn or another WSGI server
    app.run(debug=True)