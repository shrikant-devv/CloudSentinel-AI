
from sqlalchemy import text
from app.database import engine

try:
    with engine.connect() as connection:
        result = connection.execute(
            text("SELECT current_database(), current_user")
        )
        print("Database connected successfully!")
        print(result.fetchone())

except Exception as error:
    print("Database connection failed:", error)
