import datetime
import re
from fuzzywuzzy import fuzz
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from urllib.parse import urlparse

DATABASE_URL = "sqlite:///./phishguard.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String)
    status = Column(String)
    score = Column(Integer)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class FeedbackRecord(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String)
    label = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ScanRequest(BaseModel):
    url: str

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def analyze_url(url):
    parsed = urlparse(url)
    host = parsed.netloc.lower().replace("www.", "")
    path = parsed.path.lower()
    score = 0
    reasons = []

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        score += 80
        reasons.append("Uses raw IP address")

    brands = ["google", "paypal", "amazon", "microsoft"]
    for b in brands:
        ratio = fuzz.ratio(host.split('.')[0], b)
        if 75 <= ratio < 100:
            score += 65
            reasons.append(f"Mimics {b.capitalize()}")

    if any(k in path for k in ["login", "verify", "secure"]) and not any(k in host for k in brands):
        score += 40
        reasons.append("Security keywords in path of unknown domain")

    status = "safe" if score < 30 else "suspicious" if score < 70 else "malicious"
    return score, status, reasons

@app.get("/")
def read_root():
    return {
        "status": "online",
        "system": "PhishGuard Threat Engine API",
        "docs": "/docs"
    }


@app.post("/scan")
def scan(req: ScanRequest, db: Session = Depends(get_db)):
    score, status, reasons = analyze_url(req.url)
    record = ScanRecord(url=req.url, status=status, score=score)
    db.add(record)
    db.commit()
    return {"status": status, "score": score, "reasons": reasons}

@app.post("/feedback")
def feedback(url: str, label: str, db: Session = Depends(get_db)):
    record = FeedbackRecord(url=url, label=label)
    db.add(record)
    db.commit()
    return {"message": "Report received"}

@app.get("/history")
def history(db: Session = Depends(get_db)):
    return db.query(ScanRecord).order_by(ScanRecord.timestamp.desc()).limit(20).all()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
