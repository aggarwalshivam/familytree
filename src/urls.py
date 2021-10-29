from src.main import api
from src import resources

api.add_resource(resources.UserResource, '/user/')
api.add_resource(resources.UserLogin, '/user/login/')
api.add_resource(resources.PersonResource, '/person/')
api.add_resource(resources.PersonsResource, '/persons/')