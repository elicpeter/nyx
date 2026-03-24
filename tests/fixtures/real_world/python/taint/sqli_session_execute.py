import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

def search_users():
    name = os.environ.get("USERNAME")
    engine = create_engine("sqlite:///app.db")
    session = Session(engine)
    result = session.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return result.fetchall()
