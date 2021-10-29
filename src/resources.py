"""
File where we create API resources
"""
import traceback
from datetime import datetime

from flask import request
from flask_jwt_extended import (create_refresh_token,
                                jwt_refresh_token_required, get_jwt_identity)
from flask_restful import Resource, reqparse
from sqlalchemy.exc import IntegrityError

from src.main import logger, db
from src.models import User, Person, Relationshipmap
from src.constants import relation_mapper,relations
from src.schemas import PersonSchema


class UserLogin(Resource):
    """
    Restful resource for logging in user
    """

    parser = reqparse.RequestParser()

    def post(self):

        # adding arguments to data parser for required
        # fields
        self.parser.add_argument('email',
                                 help='Email cannot be blank',
                                 required=True)
        self.parser.add_argument('password',
                                 help='Password cannot be blank',
                                 required=True)

        data = self.parser.parse_args(strict=True)

        user = User.query.filter_by(email=data["email"]).first()

        if not user:
            logger.info(
                "request from {0} to {1} failed because of wrong email/"
                "unregistered number ({2}) is entered.".format(
                    request.remote_addr, request.path, data["email"]))
            return {
                'message':
                'Please check your email {0}/ If not registered, '
                'kindly register with us.'.format(data["email"])
            }, 401

        if user.check_password(data["password"], user.password):
            logger.info(
                "request from {0} for user login request is successful for "
                "email {1}".format(request.remote_addr,
                                          data["email"]))
            db.session.commit()
            print(user.id,type(user.id))
            refresh_token = create_refresh_token(user.id)
            return {
                'message': 'Logged in as {0}'.format(data["email"]),
                'refresh_token': refresh_token
            }, 200
        else:
            logger.info(
                "request from {0} for user login request is failed for "
                "email {1} because of wrong password.".format(
                    request.remote_addr, data["email"]))
            return {'message': 'Kindly check your password.'}, 404


class UserResource(Resource):
    """
    Resource for creating user
    """

    parser = reqparse.RequestParser()

    def post(self):

        self.parser.add_argument('email',
                                 help='email cannot be blank',
                                 required=True)
        self.parser.add_argument('password',
                                 help='Password cannot be blank',
                                 required=True)

        data = self.parser.parse_args(strict=True)

        user = User.query.filter_by(email=data["email"]).first()

        if user:
            return {
                "data": {
                    "error_message": "email already exists"
                }
            }, 409
        else:
            new_user = User(**data)
            new_user.pre_commit_setup()
            try:
                db.session.add(new_user)
                db.session.commit()
            except IntegrityError:
                return {
                    "data": {
                        "error_message": "email already exists"
                    }
                }, 409
            return {
                "data": {
                    "success_message": "User created successfully.",
                    "email": data["email"]
                }
            }, 201

class PersonsResource(Resource):
	
    @jwt_refresh_token_required
    def get(self):
        person = Person.query.filter_by().all()
        person_schema = PersonSchema(many=True)
        data = {} 
        data["users"]= person_schema.dump(person)
        data['relations'] = relations
        return {"data": data}, 200


class PersonResource(Resource):
    """
    Resource for Person
    """

    parser = reqparse.RequestParser()
	
    def get_relationship(self,person_id,relation,final_relative,level=0):
        temp_relative = []
        relatives = Relationshipmap.query.filter_by(to_user=person_id,relation=relation).all()
        rev_relatives = Relationshipmap.query.filter_by(relative_user=person_id,relation=relation_mapper.get(relation,relation)).all()
        for relative in relatives:
            person = Person.query.filter_by(id=relative.relative_user).first()
            person.level = level
            temp_relative.append(person)
        for relative in rev_relatives:
            person = Person.query.filter_by(id=relative.to_user).first()
            person.level = level
            temp_relative.append(person)
        final_relative.extend(temp_relative)
        if temp_relative and relation == 'Child':
            for relative in temp_relative:
                self.get_relationship(relative.id,relation,final_relative,level+1)
				
    @jwt_refresh_token_required
    def get(self):
        final_relative = []
        self.parser.add_argument('person_id', location='args')
        self.parser.add_argument('relation', location='args')
        data = self.parser.parse_args()
        self.get_relationship(data['person_id'],data['relation'],final_relative)	
        person_schema = PersonSchema(many=True)
        return {"data": person_schema.dump(final_relative)}, 200
