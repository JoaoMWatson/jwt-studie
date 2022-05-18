import os
from os.path import dirname, join

from dotenv import load_dotenv

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

_PASS = str(os.environ.get('PASSWORD'))

MONGO_CONNECT_STRING = f'mongodb+srv://jwt_app:{_PASS}@pensa-bot.dcwas.mongodb.net/?retryWrites=true&w=majority'

EMAIL_REGEX = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
