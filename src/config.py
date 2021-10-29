import os

basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = "postgresql://{0}:{1}@{2}:{4}/{3}".format(
    os.environ.get('DB_USER'), os.environ.get('DB_PASSWORD'),
    os.environ.get('DB_HOST'), os.environ.get('DB_NAME'),
    os.environ.get('DB_PORT'))
if os.environ.get('DATABASE_URL'):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://','postgresql://')
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = os.environ.get('SECRET_KEY')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
PROPAGATE_EXCEPTIONS = True
