import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base


engine = create_engine('sqlite:///var/lib/myproxy-oauth/myproxy-oauth.db', convert_unicode=True)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False,
        bind=engine))

Base = declarative_base()
Base.query = db_session.query_property()


class Admin(Base):
    __tablename__ = 'admin'

    username = Column('username', String, primary_key=True)

    def __init__(self, username):
        self.username = username


class Client(Base):
    __tablename__ = 'clients'

    oauth_consumer_key = Column(String, unique=True, nullable=False,
            primary_key=True)
    oauth_client_pubkey = Column(String)
    name = Column(String)
    home_url = Column(String)
    myproxy_server = Column(String)
    limited_proxy = Column(Integer, default=0)


class Transaction(Base):
    __tablename__ = 'transactions'

    temp_token = Column(String, unique=True, primary_key=True)
    temp_token_valid = Column(Integer)
    oauth_callback = Column(String)
    certreq =Column(String)
    oauth_consumer_key = Column(String)
    oauth_verifier = Column(String, unique=True)
    access_token = Column(String, unique=True)
    access_token_valid = Column(Integer)
    certificate = Column(String)
    username = Column(String)
    certlifetime = Column(Integer)
    timestamp = Column(Integer)

def init_db():
    Base.metadata.create_all(bind=engine)

