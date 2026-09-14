import os
import json
from datetime import datetime
from typing import Optional
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Float, Text
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class Vendor(Base):
    __tablename__ = 'vendors'
    oui = Column(String, primary_key=True)
    brand = Column(String)
    oem_group = Column(String)
    country_hint = Column(String)
    vdp_url = Column(String)
    contact = Column(String)
    notes = Column(Text)

class Model(Base):
    __tablename__ = 'models'
    id = Column(Integer, primary_key=True, autoincrement=True)
    brand = Column(String)
    model = Column(String)
    wps_default = Column(Boolean)
    wps_version = Column(String)
    pixie_class = Column(String)
    pin_class = Column(String)
    default_wpa_class = Column(String)
    mgmt_default_class = Column(String)
    eol = Column(Boolean, default=False)
    last_fw_known = Column(String)
    isp_locked_fw = Column(Boolean, default=False)
    notes = Column(Text)

class Run(Base):
    __tablename__ = 'runs'
    id = Column(String, primary_key=True) # UUID
    target_bssid = Column(String)
    target_ssid = Column(String)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    status = Column(String)
    path_taken = Column(String)

class WidsAlert(Base):
    __tablename__ = 'wids_alerts'
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    alert_type = Column(String)
    severity = Column(String)
    source_mac = Column(String)
    dest_mac = Column(String)
    channel = Column(Integer)
    frame_count = Column(Integer)
    details_json = Column(Text)

class CountermeasureTest(Base):
    __tablename__ = 'countermeasure_tests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String)
    target_hash = Column(String)
    countermeasure_type = Column(String)
    state_before = Column(String)
    state_after = Column(String)
    effective = Column(Boolean)
    delta_score = Column(Integer)

class ThreatModel(Base):
    __tablename__ = 'threat_models'
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_hash = Column(String)
    stride_category = Column(String)
    threat_description = Column(String)
    likelihood = Column(Integer)
    impact = Column(Integer)
    risk_level = Column(String)
    mitigated = Column(Boolean)

class ResilienceTest(Base):
    __tablename__ = 'resilience_tests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String)
    test_type = Column(String)
    metric_name = Column(String)
    metric_value = Column(Float)
    unit = Column(String)

class GovernanceAssessment(Base):
    __tablename__ = 'governance_assessments'
    id = Column(Integer, primary_key=True, autoincrement=True)
    target_hash = Column(String)
    isp = Column(String)
    oem = Column(String)
    agmm_level = Column(Integer)
    assessment_date = Column(DateTime, default=datetime.utcnow)

class RunTimeline(Base):
    __tablename__ = 'run_timeline'
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String)
    target_hash = Column(String)
    date = Column(DateTime, default=datetime.utcnow)
    ass_crypto = Column(Integer)
    ass_config = Column(Integer)
    ass_governance = Column(Integer)
    ass_resilience = Column(Integer)
    ass_total = Column(Integer)

class PhaseResult(Base):
    __tablename__ = 'phase_results'
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, index=True)
    phase = Column(String)
    result = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

def init_db(db_path: str):
    engine = create_engine(f'sqlite:///{db_path}')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def record_run(session, run_id: str, ssid: str, bssid: str, status: str,
               path_taken: list, phase_results: Optional[dict] = None) -> None:
    """Persiste una run + resultados por fase. Reutiliza/crea tablas existentes."""
    from datetime import datetime
    session.add(Run(
        id=run_id, target_bssid=bssid, target_ssid=ssid,
        start_time=datetime.utcnow(), end_time=datetime.utcnow(),
        status=status, path_taken=" -> ".join(path_taken),
    ))
    for phase, pres in (phase_results or {}).items():
        session.add(PhaseResult(run_id=run_id, phase=phase, result=pres))
    session.commit()
