from typing import List, Dict, Any
from .models import TargetInfo, Profile, ThreatModelSTRIDE

def calculate_stride_threat(target: TargetInfo, profile: Profile) -> ThreatModelSTRIDE:
    """Calculates the STRIDE threat model based on target info and profile."""
    stride = ThreatModelSTRIDE()
    
    if target.wps_enabled:
        if target.wps_locked:
            stride.information_disclosure += 1  # Lockout mitigates brute force, but WPS is still on
        else:
            stride.tampering += 5
            stride.information_disclosure += 2
            
            if profile.pin_class != "unknown":
                stride.elevation_of_privilege += 8  # Generic PIN known
                
            if target.wps_version == "1.0":
                stride.information_disclosure += 4 # Pixie Dust vulnerable
            
    if target.encryption in ["WEP", "Open"]:
        stride.spoofing += 10
        stride.tampering += 10
        stride.information_disclosure += 10
        stride.elevation_of_privilege += 10
        
    if profile.isp_locked_fw or profile.last_fw_known:
        # Firmware issues lead to repudiation and persistence/tampering
        stride.tampering += 3
        stride.repudiation += 4
        
    # Baseline DoS risk for all WiFi (Deauth)
    stride.denial_of_service += 5
    if target.wpa3_supported:
        # WPA3 mitigates offline dictionary attacks (SAE)
        stride.information_disclosure = max(0, stride.information_disclosure - 3)
        stride.tampering = max(0, stride.tampering - 2)
        
    if target.dpp_supported:
        stride.elevation_of_privilege = max(0, stride.elevation_of_privilege - 1)
        
    return stride

def decide_path(target: TargetInfo, profile: Profile, wids_enabled: bool = False, dry_run: bool = False) -> List[str]:
    """
    Motor de decision v2
    Returns an ordered list of actions/paths to execute.
    """
    path = []
    
    # Simulación STRIDE
    stride = calculate_stride_threat(target, profile)
    
    if wids_enabled:
        path.append("START_WIDS_MONITORING")

    if target.encryption in ["Open", "WEP"]:
        path.extend(["CLASSIFY_WEAK_CRYPTO", "REPORT"])
        return path
        
    if target.wps_locked:
        path.append("DETECT_WPS_LOCKOUT")
        # If locked, brute force is not viable, skip to EOL
    elif target.wps_enabled and profile.pin_class != "unknown":
        path.extend(["CAPTURE_HANDSHAKE", "PSK_DEFAULTS", "WPS_CLASS", "VALIDATE_COUNTERMEASURE"])
    elif target.wps_enabled and target.wps_version == "1.0":
        path.extend(["CAPTURE_HANDSHAKE", "PSK_DEFAULTS", "WPS_PIXIE", "VALIDATE_COUNTERMEASURE"])
    elif not target.wps_enabled:
        if target.wpa3_supported:
            path.append("DETECT_WPA3_SAE")
            # WPA3 SAE is resistant to offline dictionary attacks
            # We skip PSK_ROCKYOU to avoid wasting compute time
        else:
            # Fallback to SSID derivation or pure dictionary if RSN IE shows PMKID support
            path.extend(["CAPTURE_PMKID", "PSK_DEFAULTS", "PSK_SSID_LOGIC", "PSK_ROCKYOU"])
            
    if target.dpp_supported:
        path.append("AUDIT_DPP_VULNERABILITIES")
        
    if profile.isp_locked_fw:
        path.append("EOL_GOVERNANCE")
        
    path.append("AUDIT_LAN_SURFACE")
    path.append("RESILIENCE_TEST")
    path.append("REPORT")
    
    return path
