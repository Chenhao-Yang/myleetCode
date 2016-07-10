from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager

app = Flask(__name__)
app.config.from_object("config")

db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager= LoginManager(app)
login_manager.session_protection = "strong"
login_manager.login_view = "login"

from app import view
from app.models import Permission
