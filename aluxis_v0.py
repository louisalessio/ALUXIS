import socket

protocols = {
    21: "FTP (Non sicuro - Alto rischio)",
    22: "SSH (Sicuro se configurato)",
    23: "Telnet (CRITICO - Da disabilitare)",
    80: "HTTP (In chiaro - Rischio)",
    443: "HTTPS (Sicuro)"
}

target = "127.0.0.1"

print(f"--- [ALUXIS] NIS2 Audit Init: {target} ---")

for port, name in protocols.items():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target, port))
    if result == 0:
        print(f"[!] {name} rilevato sulla porta {port}")
    else:
        print(f"[OK] Porta {port} chiusa.")
    s.close()