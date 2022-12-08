from flask import Flask 
from database.db import initialize_db
from flask_restful import Api
from resources.routes import initialize_routes
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager 


app = Flask(__name__)
app.config.from_envvar('ENV_FILE_LOCATION')
api = Api(app)
jwt = JWTManager(app)

app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb+srv://group-3-software-design:YCpTgKjSJYY17sBF@consultsched.81dxtxh.mongodb.net/?retryWrites=true&w=majority'
}

initialize_db(app)
initialize_routes(api)

if __name__ == '__main__':
    app.run()