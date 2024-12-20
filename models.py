# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    topics = db.relationship('Topic', backref='author', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'
    def get_remaining_votes(self, topic_id):
        vote_record = VoteRecord.query.filter_by(
            user_id=self.id,
            topic_id=topic_id
        ).first()
        if not vote_record:
            return 2  # No votes used yet
        return 2 - vote_record.vote_count
    def get_vote_count(self, topic_id):
        # Simply count all votes for this user on this topic
        return VoteRecord.query.filter_by(
            user_id=self.id,
            topic_id=topic_id
        ).count()

    def has_voted_on(self, topic_id):
        return VoteRecord.query.filter_by(
            user_id=self.id,
            topic_id=topic_id
        ).first() is not None

    def get_total_votes_used(self):
        return VoteRecord.query.filter_by(user_id=self.id).count()

    def get_total_available_votes(self):
        total_topics = Topic.query.count()
        return total_topics * 2








class Topic(db.Model):
    __tablename__ = 'topics'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False, unique=True)
    description = db.Column(db.Text)
    votes = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    votes_record = db.relationship('VoteRecord', backref='topic', lazy=True)
    completed = db.Column(db.Boolean, default=False)
    completed_at = db.Column(db.DateTime, nullable=True)



    def __repr__(self):
        return f'<Topic {self.title}>'

class VoteRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('topics.id'), nullable=False)
    
    def __repr__(self):
        return f'<Vote {self.user_id} on {self.topic_id}>'
