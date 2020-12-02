from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from main import db, app

migrate = Migrate(app,  db)
manag = Manager(app)
manag.add_command('db', MigrateCommand)

if __name__ == "__main__":
    manag.run()