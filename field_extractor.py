"""
Guardian SIEM - Field Extraction
=================================
Turns a text event ("Event ID 4769: ... Ticket Encryption Type: 0x17 ...")
into the structured fields Sigma rules are written against (EventID,
TicketEncryptionType, TargetImage, ...), plus the logsource product and
category the rule's `logsource` block filters on.

Without this step a Sigma selection such as `EventID: 4769` has nothing to
compare against, and the rule can never fire.
"""

import re

# "Event ID 10:", "EventID: 4625", "Event 4625:" (log_ingestor's format)
_EVENT_ID = re.compile(r"\bEvent\s?(?:ID)?[:\s]\s*(\d{1,5})\b", re.IGNORECASE)

# "Key: value" pairs. A key is one to four capitalised words ("Logon Type",
# "Ticket Encryption Type", "SourceImage") that is followed by ": ".
_KEY = re.compile(r"(?:^|(?<=[\s.;,]))((?:[A-Z][A-Za-z]*)(?: [A-Z][A-Za-z]*){0,3}):\s")

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Names used by other log formats, mapped to the Sysmon / Security log names.
_ALIASES = {
    "SourceIP": "IpAddress",
    "SourceNetworkAddress": "IpAddress",
    "ClientAddress": "IpAddress",
    "TicketEncryption": "TicketEncryptionType",
    "Service": "ServiceName",
    "ServiceFileName": "ImagePath",
    "Account": "TargetUserName",
    "Target": "TargetUserName",
    "Subject": "SubjectUserName",
}

# Sysmon and Security event IDs -> Sigma logsource category.
_CATEGORY_BY_EVENT = {
    ("sysmon", 1): "process_creation",
    ("sysmon", 3): "network_connection",
    ("sysmon", 10): "process_access",
    ("sysmon", 11): "file_event",
    ("security", 4688): "process_creation",
}

_PRODUCT_BY_SOURCE = (
    ("windows", "windows"),
    ("filemonitor", "windows"),
    ("network", "network"),
    ("firewall", "network"),
    ("dns", "network"),
    ("linux", "linux"),
    ("syslog", "linux"),
)


def _clean(value):
    value = value.strip().rstrip(".,;").strip()
    # "10 (RemoteInteractive)" -> keep both parts available, see LogonType below
    return value


def extract_fields(source, message):
    """
    Extract structured fields from one event.

    Returns a dict that always has `product` and `category` keys (possibly
    empty) and any of EventID, Image, CommandLine, TargetImage, SourceImage,
    GrantedAccess, LogonType, IpAddress, TicketEncryptionType, ServiceName,
    ImagePath, TargetUserName, ... that the message contains.
    """
    fields = {}
    message = message or ""
    source_l = (source or "").lower()

    m = _EVENT_ID.search(message)
    if m:
        fields["EventID"] = m.group(1)

    keys = list(_KEY.finditer(message))
    for i, km in enumerate(keys):
        end = keys[i + 1].start() if i + 1 < len(keys) else len(message)
        name = km.group(1).replace(" ", "")
        name = _ALIASES.get(name, name)
        value = _clean(message[km.end():end])
        if value and name not in fields:
            fields[name] = value

    # "Logon Type: 10 (RemoteInteractive)" or "Logon Type 10" -> "10"
    lt = re.search(r"Logon\s?Type:?\s*(\d+)", message, re.IGNORECASE)
    if lt:
        fields["LogonType"] = lt.group(1)

    # "0x17 (RC4-HMAC)" -> "0x17"
    if "TicketEncryptionType" in fields:
        fields["TicketEncryptionType"] = fields["TicketEncryptionType"].split()[0]

    if "IpAddress" not in fields:
        ip = _IPV4.search(message)
        if ip:
            fields["IpAddress"] = ip.group(0)
    else:
        ip = _IPV4.search(fields["IpAddress"])
        fields["IpAddress"] = ip.group(0) if ip else fields["IpAddress"]

    fields["product"] = next((p for key, p in _PRODUCT_BY_SOURCE if key in source_l), "")

    channel = "sysmon" if "sysmon" in source_l else "security"
    category = ""
    if "EventID" in fields:
        category = _CATEGORY_BY_EVENT.get((channel, int(fields["EventID"])), "")
    if not category and "filemonitor" in source_l:
        category = "file_event"
    if not category and "powershell" in source_l:
        category = "ps_script"
    fields["category"] = category

    return fields
