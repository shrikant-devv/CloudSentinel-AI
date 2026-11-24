
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.bedrock import analyze_security_event
from app.database import SessionLocal, Base, engine
from app.models import ThreatRecord


app = FastAPI(
    title="CloudSentinel AI",
    description="AI-powered AWS Cloud Security Threat Analyzer",
    version="1.0.0"
)


# Request model for updating incident status
class StatusUpdate(BaseModel):
    status: str


# Create database tables if they do not exist
Base.metadata.create_all(bind=engine)


# Frontend connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "Welcome to CloudSentinel AI",
        "status": "Running",
        "service": "AI Security Analyzer"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "bedrock": "Amazon Nova Lite",
        "database": "PostgreSQL"
    }


@app.post("/analyze")
def analyze_event(event: dict):
    db = SessionLocal()

    try:
        result = analyze_security_event(event)

        record = ThreatRecord(
            threat_type=result.get(
                "threat",
                result.get("threat_type", "Unknown")
            ),
            risk_level=result.get("risk_level", "Unknown"),
            event_data=event,
            analysis_data=result
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        return {
            "success": True,
            "message": "Threat analysis saved successfully",
            "record_id": record.id,
            "analysis": result
        }

    except Exception as error:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

    finally:
        db.close()


@app.get("/history")
def get_threat_history():
    db = SessionLocal()

    try:
        records = (
            db.query(ThreatRecord)
            .order_by(ThreatRecord.created_at.desc())
            .all()
        )

        return {
            "success": True,
            "total_records": len(records),
            "history": [
                {
                    "id": record.id,
                    "threat_type": record.threat_type,
                    "risk_level": record.risk_level,
                    "event_data": record.event_data,
                    "analysis_data": record.analysis_data,
                    "status": record.status,
                    "created_at": record.created_at.isoformat()
                }
                for record in records
            ]
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )

    finally:
        db.close()


@app.patch("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    payload: StatusUpdate
):
    db = SessionLocal()

    try:
        allowed_statuses = [
            "Open",
            "Investigating",
            "Resolved"
        ]

        if payload.status not in allowed_statuses:
            raise HTTPException(
                status_code=400,
                detail="Invalid incident status"
            )

        incident = (
            db.query(ThreatRecord)
            .filter(ThreatRecord.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(
                status_code=404,
                detail="Incident not found"
            )

        incident.status = payload.status

        db.commit()
        db.refresh(incident)

        return {
            "success": True,
            "message": "Incident status updated successfully",
            "incident_id": incident.id,
            "status": incident.status
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
