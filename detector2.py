#!/home/chadi/anaconda3/envs/furrsah38/bin/python
import sys
import time
import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP, ARP

MODEL_PATH    = "model_3_pipeline.pkl"
FEATURE_ORDER = [
    'proto','service','duration','orig_bytes','resp_bytes',
    'conn_state','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes'
]
THRESHOLD     = 0.65
LOG_FILE   = "logs.txt"

pipe = joblib.load(MODEL_PATH)
print("Pipeline loaded.")

# — Extract the encoder’s learned categories —
ord_enc = pipe.named_steps['preprocessor'] \
             .named_transformers_['ord']
PROTO_CATS, SERVICE_CATS, STATE_CATS = ord_enc.categories_

# — Choose safe fallbacks (first category in each array) —
FALLBACK_PROTO      = PROTO_CATS[0]
FALLBACK_SERVICE    = SERVICE_CATS[0]
FALLBACK_CONN_STATE = STATE_CATS[0]

def clamp(val, allowed, fallback):
    return val if val in allowed else fallback

def packet_to_features(pkt):
    # 1) proto
    if pkt.haslayer(TCP):   proto = 'tcp'
    elif pkt.haslayer(UDP): proto = 'udp'
    elif pkt.haslayer(ARP): proto = 'arp'
    else:                   proto = 'icmp'
    proto = clamp(proto, PROTO_CATS, FALLBACK_PROTO)

    # 2) service by port
    if pkt.haslayer(TCP):
        port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        port = pkt[UDP].dport
    else:
        port = 0

    if port == 80:
        svc = 'http'
    elif port == 443:
        svc = 'http_443'
    elif port == 53:
        svc = 'domain'
    else:
        svc = FALLBACK_SERVICE
    service = clamp(svc, SERVICE_CATS, FALLBACK_SERVICE)

    # 3) conn_state: any ACK‐bearing TCP as 'SF'
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags & 0x10:    # ACK bit set (includes PSH+ACK, FIN+ACK)
            c = 'SF'
        else:
            c = FALLBACK_CONN_STATE
    else:
        c = FALLBACK_CONN_STATE
    conn_state = clamp(c, STATE_CATS, FALLBACK_CONN_STATE)

    # 4) numeric features
    length = float(len(pkt))
    return {
        'proto':         proto,
        'service':       service,
        'duration':      0.0,
        'orig_bytes':    length,
        'resp_bytes':    0.0,
        'conn_state':    conn_state,
        'orig_pkts':     1,
        'orig_ip_bytes': length,
        'resp_pkts':     0,
        'resp_ip_bytes': 0
    }

def predict(feats):
    df = pd.DataFrame([feats], columns=FEATURE_ORDER)
    prob = pipe.predict_proba(df)[0,1]
    return prob, prob > THRESHOLD

# Handle incoming packet
def handle_packet(pkt):
    if IP in pkt:
        feats = packet_to_features(pkt)
        score, mal = predict(feats)
        ts = time.strftime("%H:%M:%S")

        status = "MALICIOUS" if mal else "benign"
        log_entry = (
            f"[{ts}] {pkt.summary()}\n"
            f"   Features: {feats}\n"
            f"   Score: {score:.3f} → {status}\n"
            + "-" * 40 + "\n"
        )

        print(log_entry.strip())  # Console

        with open(LOG_FILE, "a") as f:  # Save to logs
            f.write(log_entry)


if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv)>1 else "lo"
    print(f" Sniffing on {iface}")
    sniff(iface=iface, prn=handle_packet, store=False)


