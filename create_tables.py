
from app.database import Base, engine
from app import models

# Create all tables defined in models.py
Base.metadata.create_all(bind=engine)

print("Threat records table created successfully!")
