# callable application is imported so that we can pass it to wsgi server.

from src import app

if __name__ == '__main__':
    app.run('0.0.0.0', '7000', debug=True)
