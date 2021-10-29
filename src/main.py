"""
In this file we initialize the flask app and add configurations to it.
We initialize API, jwt and db extensions using the app
"""

import traceback
from time import strftime

from flask import Flask, request
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from logging.config import dictConfig
from flask_marshmallow import Marshmallow

from . import config

dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        }
    },
    'handlers': {
        'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://flask.logging.wsgi_errors_stream',
            'formatter': 'default'
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)
logger = app.logger
api = Api(app)
app.config.from_object(config)

jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)


# using after request decorator logging all requests
@app.after_request
def after_request(response):
    timestamp = strftime('[%Y-%b-%d %H:%M]')
    logger.info('{0} {1} {2} {3} {4} {5}'.format(
        timestamp, request.remote_addr, request.method, request.scheme,
        request.full_path, response.status))
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers[
        'Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    response.headers[
        'Access-Control-Allow-Methods'] = 'OPTIONS, GET, PUT, POST'
    response.headers['X-XSS-Protection'] = 1
    response.headers['mode'] = 'block'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


# using error handler decorator to log all the exceptions
@app.errorhandler(Exception)
def exception_handler(e):
    timestamp = strftime('[%Y-%b-%d %H:%M]')
    logger.error('{0} {1} {2} {3} {4} 500 INTERNAL SERVER ERROR\n%s',
                 timestamp, request.remote_addr, request.method,
                 request.scheme, request.full_path, traceback.format_exc())
    return e.status_code


@app.route('/health-check/', methods=["GET"])
def health_check():
    return "success"
