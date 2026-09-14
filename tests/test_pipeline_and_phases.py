"""
Tests unitarios del Pipeline y las fases de AURIS.

Estos tests NO necesitan hardware WiFi, herramientas instaladas ni radio.
Usan stubs de fases y el pipeline limpio para verificar el flujo de control.
"""

import pytest
from auris.pipeline import Pipeline, PipelineResult
from auris.phases.base import (
    PhaseResult, PhaseProtocol,
    STATUS_CRACKED, STATUS_SKIPPED, STATUS_LOCKED,
    STATUS_NOT_FOUND, STATUS_DONE, STATUS_ERROR,
)
from auris.models import TargetInfo, Profile
from auris.generator import generate_candidates, CandidateGenerator


# ─── Stubs de fases para testing ──────────────────────────────────────────────

class StubPhase:
    """Fase stub configurable para tests."""
    def __init__(self, name: str, status: str, can: bool = True,
                 credential: str = None, raise_exc: Exception = None):
        self.name = name
        self._status = status
        self._can = can
        self._credential = credential
        self._raise = raise_exc

    def can_run(self) -> bool:
        return self._can

    def run(self) -> PhaseResult:
        if self._raise:
            raise self._raise
        return PhaseResult(
            phase_name=self.name,
            status=self._status,
            credential=self._credential,
            cred_type="stub" if self._credential else None,
        )


# ─── Tests: Pipeline de control de flujo ──────────────────────────────────────

class TestPipelineFlowControl:

    def _make_registry(self, phases):
        return {p.name: p for p in phases}

    def test_executes_all_phases_in_order(self):
        """Las fases se ejecutan en el orden del path planificado."""
        order = []
        phases = [
            StubPhase("PHASE_A", STATUS_NOT_FOUND),
            StubPhase("PHASE_B", STATUS_DONE),
            StubPhase("PHASE_C", STATUS_NOT_FOUND),
        ]
        registry = self._make_registry(phases)

        def on_start(name):
            order.append(name)

        pipeline = Pipeline(registry, ["PHASE_A", "PHASE_B", "PHASE_C"],
                            on_phase_start=on_start)
        result = pipeline.run("TestSSID", "AA:BB:CC:DD:EE:FF")

        assert order == ["PHASE_A", "PHASE_B", "PHASE_C"]
        assert result.phases_executed == 3

    def test_stops_offensive_phases_after_cracked(self):
        """
        Una vez obtenida la credencial, las fases ofensivas se omiten.
        Las fases informativas (EOL, LAN) siguen ejecutándose.
        """
        phases = [
            StubPhase("WPS_PIXIE", STATUS_CRACKED, credential="mysecret"),
            StubPhase("PSK_ROCKYOU", STATUS_NOT_FOUND),    # debe omitirse
            StubPhase("EOL_GOVERNANCE", STATUS_DONE),       # debe ejecutarse
        ]
        registry = self._make_registry(phases)
        pipeline = Pipeline(registry, ["WPS_PIXIE", "PSK_ROCKYOU", "EOL_GOVERNANCE"])
        result = pipeline.run("TestSSID", "AA:BB:CC:DD:EE:FF")

        assert result.final_status == STATUS_CRACKED
        assert result.credential == "mysecret"
        assert result.phase_results["PSK_ROCKYOU"].status == STATUS_SKIPPED
        assert result.phase_results["EOL_GOVERNANCE"].status == STATUS_DONE

    def test_stops_entire_pipeline_on_lockout(self):
        """Al detectar lockout, TODAS las fases siguientes se omiten."""
        phases = [
            StubPhase("WPS_CLASS", STATUS_LOCKED),
            StubPhase("PSK_ROCKYOU", STATUS_NOT_FOUND),
            StubPhase("EOL_GOVERNANCE", STATUS_DONE),
        ]
        registry = self._make_registry(phases)
        pipeline = Pipeline(registry, ["WPS_CLASS", "PSK_ROCKYOU", "EOL_GOVERNANCE"])
        result = pipeline.run("TestSSID", "AA:BB:CC:DD:EE:FF")

        assert result.lockout_detected is True
        assert result.final_status == STATUS_LOCKED
        assert result.phase_results["PSK_ROCKYOU"].status == STATUS_SKIPPED
        assert result.phase_results["EOL_GOVERNANCE"].status == STATUS_SKIPPED

    def test_skips_phase_when_cannot_run(self):
        """Fases con can_run()=False se marcan SKIPPED automáticamente."""
        phases = [
            StubPhase("CAPTURE_PMKID", STATUS_NOT_FOUND, can=False),
        ]
        registry = self._make_registry(phases)
        pipeline = Pipeline(registry, ["CAPTURE_PMKID"])
        result = pipeline.run("TestSSID", "AA:BB:CC:DD:EE:FF")

        assert result.phase_results["CAPTURE_PMKID"].status == STATUS_SKIPPED

    def test_handles_unhandled_exception_gracefully(self):
        """Una excepción en una fase genera ERROR pero no rompe el pipeline."""
        phases = [
            StubPhase("WPS_PIXIE", STATUS_CRACKED, raise_exc=RuntimeError("chipset disconnected")),
            StubPhase("PSK_ROCKYOU", STATUS_NOT_FOUND),
        ]
        registry = self._make_registry(phases)
        pipeline = Pipeline(registry, ["WPS_PIXIE", "PSK_ROCKYOU"])
        result = pipeline.run("TestSSID", "AA:BB:CC:DD:EE:FF")

        assert result.phase_results["WPS_PIXIE"].status == STATUS_ERROR
        # El pipeline continúa con las fases siguientes
        assert result.phase_results["PSK_ROCKYOU"].status == STATUS_NOT_FOUND

    def test_phase_not_in_registry_is_skipped(self):
        """Si el path incluye una fase no en el registry, se omite limpiamente."""
        registry = {}  # Vacío
        pipeline = Pipeline(registry, ["UNKNOWN_PHASE"])
        result = pipeline.run("TestSSID", "AA:BB:CC:DD:EE:FF")

        assert result.phase_results["UNKNOWN_PHASE"].status == STATUS_SKIPPED

    def test_final_status_exhausted_when_nothing_works(self):
        """Si ninguna fase da resultado positivo, final_status = exhausted."""
        phases = [
            StubPhase("CAPTURE_PMKID", STATUS_NOT_FOUND),
            StubPhase("PSK_SSID_LOGIC", "exhausted"),
        ]
        registry = self._make_registry(phases)
        pipeline = Pipeline(registry, ["CAPTURE_PMKID", "PSK_SSID_LOGIC"])
        result = pipeline.run("TestSSID", "AA:BB:CC:DD:EE:FF")

        assert result.final_status == "exhausted"

    def test_pipeline_result_summary_line(self):
        """summary_line() produce un string legible."""
        pr = PipelineResult(
            target_ssid="MiRed", target_bssid="AA:BB:CC:DD:EE:FF",
            path_planned=["CAPTURE_PMKID", "PSK_ROCKYOU"],
            final_status=STATUS_CRACKED,
            credential="password123", cred_type="WPS PixieDust",
            elapsed_sec=45.2,
        )
        line = pr.summary_line()
        assert "MiRed" in line
        assert STATUS_CRACKED in line
        assert "WPS PixieDust" in line


# ─── Tests: CandidateGenerator ────────────────────────────────────────────────

class TestCandidateGenerator:

    def test_generates_minimum_candidates_for_any_ssid(self):
        """Siempre genera al menos algunos candidatos para cualquier SSID."""
        cs = generate_candidates("TestSSID", "AA:BB:CC:DD:EE:FF", "TP-Link")
        assert cs.total > 0
        assert len(cs.batch_1) > 0

    def test_candidates_meet_wpa_psk_length_requirement(self):
        """Todos los candidatos deben tener al menos 8 caracteres (WPA PSK mínimo)."""
        cs = generate_candidates("MyNet", "AC:CC:8A:11:22:33")
        violations = [c for c in cs.all_candidates() if len(c) < 8]
        assert violations == [], f"Short candidates: {violations[:5]}"

    def test_family_sibling_reuse(self):
        """La clave de un AP hermano aparece en el batch_1."""
        family = {"MiRed": "ClaveDelAP1"}
        cs = generate_candidates("MiRed_2", "AA:BB:CC:DD:EE:FF",
                                  family_keys=family)
        assert "ClaveDelAP1" in cs.batch_1

    def test_no_duplicate_candidates(self):
        """No hay duplicados entre batch_1 y batch_2."""
        cs = generate_candidates("Movistar_HGU", "AC:CC:8A:AB:CD:EF", "Askey")
        all_candidates = list(cs.all_candidates())
        assert len(all_candidates) == len(set(all_candidates))

    def test_bssid_fragments_included(self):
        """Los últimos octetos del BSSID generan candidatos combinados."""
        bssid = "AC:CC:8A:11:22:33"
        cs = generate_candidates("MiRed", bssid)
        # Los últimos 4 hex del BSSID deben aparecer en algún candidato
        tail = "2233"
        has_tail = any(tail.upper() in c.upper() or tail.lower() in c.lower()
                       for c in cs.batch_1)
        assert has_tail, f"BSSID tail {tail} not in any candidate"

    def test_family_mutations_in_batch_2(self):
        """Las mutaciones de claves de familia van al batch_2."""
        family = {"MiRed": "clave123"}
        cs = generate_candidates("MiRed_2", "AA:BB:CC:DD:EE:FF",
                                  family_keys=family)
        # batch_2 debe contener mutaciones de "clave123"
        has_mutation = any("clave123" in c for c in cs.batch_2)
        assert has_mutation

    def test_max_candidates_respected(self):
        """El límite max_batch_1 se respeta."""
        gen = CandidateGenerator(max_batch_1=100)
        cs = gen.generate(ssid="LongSSIDName", bssid="AA:BB:CC:DD:EE:FF")
        assert len(cs.batch_1) <= 100

    def test_to_wordlist_lines_format(self):
        """to_wordlist_lines() produce texto separado por newlines sin vacíos al inicio."""
        cs = generate_candidates("TestNet", "AA:BB:CC:DD:EE:FF")
        lines = cs.to_wordlist_lines().splitlines()
        assert len(lines) > 0
        assert all(len(l) >= 8 for l in lines if l.strip())

    def test_metadata_populated(self):
        """El campo meta del CandidateSet contiene estadísticas de fuentes."""
        cs = generate_candidates("RedTest", "AA:BB:CC:DD:EE:FF", brand="Huawei")
        assert "batch_1_total" in cs.meta
        assert "sources" in cs.meta
        assert cs.meta["batch_1_total"] == len(cs.batch_1)


# ─── Tests: Modelos ───────────────────────────────────────────────────────────

class TestModels:

    def test_target_info_new_fields(self):
        """Los nuevos campos WPS de TargetInfo tienen valores por defecto correctos."""
        target = TargetInfo(
            bssid="AC:CC:8A:11:22:33",
            ssid="TestSSID",
            channel=6,
            encryption="WPA2",
            wps_enabled=True,
            oui="ACCC8A",
            signal_strength=-65,
        )
        assert target.wps_manufacturer is None
        assert target.wps_model_number is None
        assert target.wps_pbc_active is False

    def test_stride_total_risk(self):
        """ThreatModelSTRIDE.total_risk suma todos los ejes."""
        from auris.models import ThreatModelSTRIDE
        s = ThreatModelSTRIDE(
            spoofing=2, tampering=5, repudiation=1,
            information_disclosure=4, denial_of_service=5, elevation_of_privilege=8,
        )
        assert s.total_risk == 25

    def test_pbc_event_severity(self):
        """PBCEvent auto-calcula la severidad correctamente."""
        from auris.models import PBCEvent
        ev_no_extract = PBCEvent(bssid="AA:BB:CC:DD:EE:FF", ssid="Test", channel=6)
        assert ev_no_extract.severity == "Medium"
        assert ev_no_extract.cwe_id == "CWE-287"

        ev_extracted = PBCEvent(bssid="AA:BB:CC:DD:EE:FF", ssid="Test",
                                 channel=6, psk_extracted=True)
        assert ev_extracted.severity == "High"

    def test_hal_status_summary(self):
        """HALStatus.summary describe correctamente cada estado."""
        from auris.models import HALStatus
        h_no_pyusb = HALStatus(pyusb_available=False)
        assert "PyUSB ausente" in h_no_pyusb.summary

        h_active = HALStatus(pyusb_available=True, libusb1_available=True,
                              adapters_found=2, userland_capable=True)
        assert "2 adaptador" in h_active.summary


# ─── Tests: HAL registry ──────────────────────────────────────────────────────

class TestHALRegistry:

    def test_chipset_registry_not_empty(self):
        """El registro de chipsets tiene entradas."""
        from auris import CHIPSET_REGISTRY
        assert len(CHIPSET_REGISTRY) >= 10

    def test_all_registry_entries_have_required_fields(self):
        """Cada entrada del registry tiene chipset, VID, PID y bandas."""
        from auris import CHIPSET_REGISTRY
        for (vid, pid), info in CHIPSET_REGISTRY.items():
            assert vid > 0, f"Invalid VID for {info.chipset}"
            assert pid > 0, f"Invalid PID for {info.chipset}"
            assert info.chipset, f"Missing chipset name for {vid:04X}:{pid:04X}"
            assert info.bands, f"Missing bands for {info.chipset}"

    def test_stubbed_transceiver_interface(self):
        """StubbedTransceiver cumple el contrato WirelessTransceiver."""
        from auris import StubbedTransceiver, Dot11Frame
        stub = StubbedTransceiver()
        stub.open_device()
        stub.set_channel(6)
        frames = list(stub.read_frames(timeout_ms=10))
        assert isinstance(frames, list)
        assert stub.inject_frame(b"\x00" * 24) is False
        stub.close_device()

    def test_stubbed_transceiver_with_synthetic_frames(self):
        """StubbedTransceiver devuelve frames sintéticos del canal correcto."""
        from auris import StubbedTransceiver, Dot11Frame
        import time
        synthetic = [
            Dot11Frame(timestamp=time.time(), channel=6, raw_bytes=b"\x80" + b"\x00"*23, rssi=-60),
            Dot11Frame(timestamp=time.time(), channel=11, raw_bytes=b"\x80" + b"\x00"*23, rssi=-70),
        ]
        stub = StubbedTransceiver(synthetic_frames=synthetic)
        stub.open_device()
        stub.set_channel(6)
        frames = list(stub.read_frames(timeout_ms=10))
        # Solo el frame del canal 6 debe aparecer
        assert len(frames) == 1
        assert frames[0].channel == 6


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
