from database import engine, Base
from models import User

# Create all database tables
Base.metadata.create_all(bind=engine)

print("VaultX database tables created successfully.")