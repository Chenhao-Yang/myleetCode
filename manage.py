from flask.ext.script import Manager, Shell
from app import app
from app import db
from app.models import User, Role


manager = Manager(app)


def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role)
manager.add_command("shell", Shell(make_context=make_shell_context))


if __name__ == "__main__":
    manager.run()
