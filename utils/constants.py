SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    389: "LDAP",
    445: "SMB",
    1433: "SQL Server",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

SUSPICIOUS_PORTS = {21, 22, 23, 25, 53, 135, 139, 445, 1433, 1521,
                    3306, 3389, 5432, 5900, 6379, 9200, 27017}

PROMPT_INJECTION_TERMS = [
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "developer message",
    "jailbreak",
    "bypass policy",
    "disable safety",
    "reveal prompt",
    "泄露提示词",
    "忽略以上",
    "越狱",
    "绕过安全",
]

AI_AGENT_TERMS = [
    "claude",
    "anthropic",
    "openai",
    "gpt",
    "llm",
    "autogen",
    "langchain",
    "agent",
    "browser-use",
]

WEB_ATTACK_TERMS = [
    "union select",
    "' or '1'='1",
    " or 1=1",
    "../",
    "%2e%2e",
    "<script",
    "onerror=",
    "cmd.exe",
    "/bin/sh",
    "powershell",
    "base64",
]

NORMALIZED_CATEGORIES = {
    "game": ["game", "gaming", "games"],
    "video": ["video streaming", "video", "streaming"],
    "social": ["social media", "social"],
    "chat": ["chat", "im", "instant messaging"],
    "edu": ["education", "edu", "learning"],
    "web": ["web browse", "web", "http"],
    "dns": ["dns"],
}

FEATURE_NAMES = [
    "total_bytes",
    "total_packets",
    "unique_dst_ips",
    "unique_dst_ports",
    "suspicious_port_hits",
    "night_byte_ratio",
    "dns_query_count",
    "max_hour_bytes",
    "active_hour_count",
    "avg_bytes_per_packet",
]

USER_PROFILE_SUSPICIOUS_PORTS = [22, 3389, 3306, 8000, 8080, 5000]

REALTIME_WINDOW_SIZE = 200
REALTIME_TRAFFIC_BUCKETS = 30
REALTIME_BUCKET_SECONDS = 5
REALTIME_PORT_SCAN_THRESHOLD = 6
REALTIME_PORT_SCAN_WINDOW = 30
REALTIME_LARGE_FLOW_BYTES = 50_000

ML_MIN_USERS = 5
ML_DEFAULT_CONTAMINATION = 0.1
ML_TOP_N = 10
