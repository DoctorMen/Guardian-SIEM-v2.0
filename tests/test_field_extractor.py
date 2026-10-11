"""
Tests for field_extractor.py: text events -> fields Sigma rules match on.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from field_extractor import extract_fields


def test_sysmon_process_access():
    f = extract_fields(
        "Windows_Sysmon",
        "Event ID 10: Process accessed. SourceImage: C:\\Tools\\procdump.exe. "
        "TargetImage: C:\\Windows\\System32\\lsass.exe. GrantedAccess: 0x1fffff",
    )
    assert f["EventID"] == "10"
    assert f["SourceImage"] == "C:\\Tools\\procdump.exe"
    assert f["TargetImage"] == "C:\\Windows\\System32\\lsass.exe"
    assert f["GrantedAccess"] == "0x1fffff"
    assert (f["product"], f["category"]) == ("windows", "process_access")


def test_sysmon_process_create_keeps_spaces_in_command_line():
    f = extract_fields(
        "Windows_Sysmon",
        "Event ID 1: Process Create. Image: C:\\Windows\\System32\\cmd.exe "
        "CommandLine: cmd.exe /c whoami /all ParentImage: C:\\Windows\\explorer.exe",
    )
    assert f["CommandLine"] == "cmd.exe /c whoami /all"
    assert f["ParentImage"] == "C:\\Windows\\explorer.exe"
    assert f["category"] == "process_creation"


def test_security_log_multi_word_keys_and_aliases():
    f = extract_fields(
        "Windows_EventLog",
        "Event ID 4769: A Kerberos service ticket was requested. Account Name: bob@CORP.LOCAL. "
        "Service Name: svc_sql. Ticket Encryption Type: 0x17. Client Address: ::ffff:10.1.2.3",
    )
    assert f["EventID"] == "4769"
    assert f["ServiceName"] == "svc_sql"
    assert f["TicketEncryptionType"] == "0x17"
    assert f["IpAddress"] == "10.1.2.3"
    assert f["category"] == ""


def test_logon_type_number_only():
    f = extract_fields("Windows_EventLog", "Event ID 4624: Logon Type: 10. Source Network Address: 10.0.0.9")
    assert f["LogonType"] == "10"
    assert f["IpAddress"] == "10.0.0.9"


def test_log_ingestor_format():
    f = extract_fields("Windows_Security", "Event 4625: An account failed to log on.")
    assert f["EventID"] == "4625"


def test_network_flow_falls_back_to_first_ip():
    f = extract_fields("Network_Flow", "Connection: SrcIp: 192.168.1.100. DstIp: 10.0.0.1. DstPort: 22")
    assert f["IpAddress"] == "192.168.1.100"
    assert f["DstPort"] == "22"
    assert f["product"] == "network"


def test_file_monitor_is_file_event():
    assert extract_fields("FileMonitor", "file written")["category"] == "file_event"


def test_empty_message():
    assert extract_fields("", "") == {"product": "", "category": ""}
