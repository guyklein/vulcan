from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

connection_string = 'sqlite:///:memory:'
engine = create_engine(connection_string)
Session = sessionmaker(bind=engine)

Base = declarative_base()
