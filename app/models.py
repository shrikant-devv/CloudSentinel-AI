
from sqlalchemy import Column, Integer, String, JSON, DateTime
from sqlalchemy.sql import func

from app.database import Base


class ThreatRecord(Base):
    __tablename__ = "threat_records"

    id = Column(Integer, primary_key=True, index=True)

    threat_type = Column(String(255), nullable=False)

    risk_level = Column(String(50), nullable=False)

    event_data = Column(JSON, nullable=False)

    analysis_data = Column(JSON, nullable=False)

    status = Column(
        String(30),
        nullable=False,
        default="Open",
        server_default="Open"
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
