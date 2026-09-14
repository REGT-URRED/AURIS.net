import json
from datetime import datetime
from typing import List, Dict, Any

class MITREMappper:
    """Fuente única: reutiliza el mapeo canónico de report_writer.

    Se mantiene el nombre histórico (con triple 'p') por compatibilidad.
    """

    @staticmethod
    def _mapping() -> dict:
        from .report_writer import MITRE_ATTACK
        return MITRE_ATTACK

    @staticmethod
    def map_path(path: List[str]) -> List[Dict[str, str]]:
        mapping = MITREMappper._mapping()
        mapped = []
        for step in path:
            if step in mapping:
                m = mapping[step]
                entry = {"id": m["id"], "name": m["name"]}
                if "type" in m:
                    entry["type"] = m["type"]
                mapped.append(entry)
        return mapped

class Reporter:
    def __init__(self, target_bssid: str):
        self.target = target_bssid
        self.report_time = datetime.now().isoformat()
        
    def generate_json_report(self, path: List[str], score: int, alerts: List[dict]):
        mitre_data = MITREMappper.map_path(path)
        
        report = {
            "target": self.target,
            "timestamp": self.report_time,
            "auris_score": score,
            "path_executed": path,
            "mitre_mapping": mitre_data,
            "wids_alerts_captured": len(alerts),
            "alerts": alerts
        }
        
        return json.dumps(report, indent=2)

    def print_summary(self, path: List[str], alerts: List[dict]):
        print(f"\n=========================================")
        print(f" AURIS v2 - Resumen de Ejecución")
        print(f"=========================================")
        print(f" Objetivo: {self.target}")
        print(f" Hora: {self.report_time}")
        print(f" Fases ejecutadas: {len(path)}")
        
        mitre = MITREMappper.map_path(path)
        if mitre:
            print(f"\n Mapeo MITRE (ATT&CK / D3FEND):")
            for m in mitre:
                print(f"  - [{m['id']}] {m['name']}")
                
        if alerts:
            print(f"\n Alertas Defensivas (WIDS): {len(alerts)}")
        else:
            print(f"\n Alertas Defensivas (WIDS): Ninguna (Modo sigiloso / No activo)")
            
        print(f"=========================================\n")
