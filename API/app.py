from flask import Flask, jsonify, request, session
from flask_sqlalchemy import SQLAlchemy
#from Flask.app import User

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///IBM_DB.db' # connect to db
app.config["SECRET_KEY"] = "123"

db = SQLAlchemy(app) #enable SQLAlchemy
print(db)