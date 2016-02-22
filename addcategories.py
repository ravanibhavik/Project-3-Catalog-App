from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, User, Item, Category

engine = create_engine('sqlite:///catalogapp.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

user = User(name="Bhavik", email="ravanibhavik@gmail.com")
session.add(user)
session.commit()

category = Category(name="Soccer", user_id=user.id)
session.add(category)
session.commit()

category = Category(name="Basketball", user_id=user.id)
session.add(category)
session.commit()

category = Category(name="Baseball", user_id=user.id)
session.add(category)
session.commit()

category = Category(name="Frisbee", user_id=user.id)
session.add(category)
session.commit()

category = Category(name="Snowboarding", user_id=user.id)
session.add(category)
session.commit()

category = Category(name="Rock Climbing", user_id=user.id)
session.add(category)
session.commit()

category = Category(name="Foosball", user_id=user.id)
session.add(category)
session.commit()

category = Category(name="Skating", user_id=user.id)
session.add(category)
session.commit()

category = Category(name="Hockey", user_id=user.id)
session.add(category)
session.commit()

