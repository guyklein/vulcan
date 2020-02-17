from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

engine = create_engine('mysql+pymysql://root:root@localhost:32000/vulcan')
Session = sessionmaker(bind=engine)

Base = declarative_base()