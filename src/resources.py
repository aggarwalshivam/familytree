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
from collections import defaultdict

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

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email',
                                 help='email cannot be blank',
                                 required=True)
        parser.add_argument('password',
                                 help='Password cannot be blank',
                                 required=True)

        data = parser.parse_args(strict=True)

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
        relationship = defaultdict(list)
        if not relation:
            relatives = Relationshipmap.query.filter_by(to_user=person_id).all()
            rev_relatives = Relationshipmap.query.filter_by(relative_user=person_id).all()
        else:
            relatives = Relationshipmap.query.filter_by(to_user=person_id,relation=relation).all()
            rev_relatives = Relationshipmap.query.filter_by(relative_user=person_id,relation=relation_mapper.get(relation,relation)).all()
        print("2nd checkpoint")
        for relative in relatives:
            person = Person.query.filter_by(id=relative.relative_user).first()
            person.level = level
            person_schema = PersonSchema()
            if not relation:
                relationship[relative.relation].append((relative.id, False,person_schema.dump(person)))
            else:
                temp_relative.append(person)
        for relative in rev_relatives:
            person = Person.query.filter_by(id=relative.to_user).first()
            person.level = level
            person_schema = PersonSchema()
            if not relation:
                relationship[relation_mapper.get(relative.relation,relative.relation)].append((relative.id, True,person_schema.dump(person)))
            else:
                temp_relative.append(person)
        if relation:
            final_relative.extend(temp_relative)
        if relation and temp_relative and relation == 'Child':
            for relative in temp_relative:
                self.get_relationship(relative.id,relation,final_relative,level+1)
        return relationship
				
    @jwt_refresh_token_required
    def get(self):
        final_relative = []
        print("INN RELATION")
        self.parser.add_argument('person_id', location='args')
        self.parser.add_argument('relation', location='args',required=False)
        data = self.parser.parse_args()
        relationship = self.get_relationship(data['person_id'],data.get('relation',''),final_relative)	
        if data.get('relation'):
            person_schema = PersonSchema(many=True)
            return {"data": person_schema.dump(final_relative)}, 200
        else:
            return {"data": relationship},200



class RelationshipResource(Resource):

    @jwt_refresh_token_required
    def delete(self,id=None):    

        relation = Relationshipmap.query.filter_by(id=id).first()

        db.session.delete(relation)
        db.session.commit()
        return {
                "data": {
                    "success_message": "Relation deleted successfully.",
                }
            }, 201
        
    @jwt_refresh_token_required
    def patch(self):
        parser = reqparse.RequestParser()
        parser.add_argument('id',
                                help='ID to be deleted cannot be blank',
                                required=True,location='json')
        parser.add_argument('relation',
                                help='New relation to be deleted cannot be blank',
                                required=True)
        parser.add_argument('reverse',
                                help='reverse cannot be blank',
                                required=True,
                                type=bool)
        
        data = parser.parse_args(strict=True)
        print(data['reverse'],type(data['reverse']),data['relation'])
        if data['reverse']:
            Relationshipmap.query.filter_by(id=data["id"]).update({'relation':relation_mapper.get(data['relation'],data['relation'])})
        else:
            Relationshipmap.query.filter_by(id=data["id"]).update({'relation':data['relation']})
        
        db.session.commit()
        return {
                "data": {
                    "success_message": "Relation updated successfully.",
                }
            }, 201
    @jwt_refresh_token_required
    def post(self,id=None):
        parser = reqparse.RequestParser()
        parser.add_argument('relative_user',
                                 help='First Name cannot be blank',
                                 required=True)
        parser.add_argument('relation',
                                 help='Last Name cannot be blank',
                                 required=True)
        
        data = parser.parse_args(strict=True)
        rel = {'to_user':id,'relative_user':data['relative_user'],'relation':data['relation']}
        relatives = Relationshipmap.query.filter_by(to_user=rel['to_user'],relative_user=rel['relative_user']).first()
        if relatives:
             return {
                "data": {
                    "success_message": "Relation already exists!",
                }
            }, 409
        rev_relative = Relationshipmap.query.filter_by(relative_user=rel['to_user'],to_user=rel['relative_user']).first()
        if rev_relative:
            return {
                "data": {
                    "success_message": "Relation already exists!",
                }
            }, 409
        rel = Relationshipmap(**rel)
        db.session.add(rel)
        db.session.commit()
        return {
                "data": {
                    "success_message": "Relation created successfully.",
                }
            }, 201

class CreatePersonResource(Resource):
    """
    Resource for creating user
    """

    def post(self):

        parser = reqparse.RequestParser()

        parser.add_argument('first_name',
                                 help='First Name cannot be blank',
                                 required=True)
        parser.add_argument('last_name',
                                 help='Last Name cannot be blank',
                                 required=True)
        parser.add_argument('phone_number',
                                 help='Phone number cannot be blank',
                                 required=True)
        parser.add_argument('email_address',
                                 help='Email Address cannot be blank',
                                 required=True)
        parser.add_argument('birth_date',
                                 type=lambda x: datetime.strptime(x,'%d/%m/%Y'),
                                 help='Date of birth cannot be blank',
                                 required=True)
        parser.add_argument('address',
                                 help='Address cannot be blank',
                                 required=True)

        data = parser.parse_args(strict=True)

        person = Person.query.filter_by(email_address=data["email_address"]).first()

        if person:
            return {
                "status":"fail",
                    "error_message": "Person already exists"
            }, 200
        else:
            new_person = Person(**data)
            try:
                db.session.add(new_person)
                db.session.commit()
            except IntegrityError:
                return {
                        "status":"fail",
                        "error_message": "email already exists"
                }, 200
            return {
                    "status":"success",
                    "success_message": "Person created successfully."
                
            }, 201