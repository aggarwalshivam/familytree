import uuid
from datetime import datetime
from itertools import chain

from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.hybrid import hybrid_property
from passlib.hash import django_pbkdf2_sha256

from src.main import db


class User(db.Model):
    """
    User model for storing user data
    """
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    

    @classmethod
    def check_password(cls, password, _hash):
        return django_pbkdf2_sha256.verify(password, _hash)

    def pre_commit_setup(self):
        """
        This method generates the required fields either from available
        information else automatic fields are generated.
        """
        self.password = django_pbkdf2_sha256.hash(self.password)


class Relationshipmap(db.Model):
    """
    Model for relationship mapping
    """
    __tablename__ = "relationshipmap"

    id = db.Column(db.Integer, primary_key=True)
    to_user = db.Column(db.Integer, db.ForeignKey('person.id'), nullable=False)
    relative_user = db.Column(db.Integer,db.ForeignKey('person.id'), nullable=False)
    relation = db.Column(db.String(128))


class Person(db.Model):
    """
    Model for person
    """

    __tablename__ = "person"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(128), nullable=False)
    phone_number = db.Column(db.String(10), nullable=False)
    email_address = db.Column(db.String(128), nullable=False)
    birth_date = db.Column(db.Date, nullable=False)
    address = db.Column(db.String(128), nullable=False)
    level = db.Column(db.Integer,nullable=True)
