from src.main import api
from src import resources

api.add_resource(resources.UserResource, '/user/')
api.add_resource(resources.UserLogin, '/user/login/')
api.add_resource(resources.PersonResource, '/person/')
api.add_resource(resources.PersonsResource, '/persons/')
api.add_resource(resources.CreatePersonResource, '/createperson/')
api.add_resource(resources.RelationshipResource, '/relation/', '/relation/<id>/','/person/<id>/relation/')