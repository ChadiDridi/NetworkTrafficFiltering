#!/home/chadi/anaconda3/envs/furrsah38/bin/python
import sys, time
import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP, ARP

MODEL_PATH    = "model_4_pipeline_ordinal.pkl"
FEATURE_ORDER = ['proto','service','duration','orig_bytes','resp_bytes','conn_state']
THRESHOLD     = 0.65
LOG_FILE      = "logs.txt"  # Add log file path

# Load the trained pipeline
pipe = joblib.load(MODEL_PATH)
print("Pipeline loaded.")

# Grab the encoder’s learned string categories
ord_enc = pipe.named_steps['preprocessor'].named_transformers_['ord']
PROTO_CATS, SERVICE_CATS, STATE_CATS = ord_enc.categories_
FALLBACK_PROTO      = PROTO_CATS[0]
FALLBACK_SERVICE    = SERVICE_CATS[0]
FALLBACK_CONN_STATE = STATE_CATS[0]

def clamp(val, allowed, fallback):
    return val if val in allowed else fallback

def packet_to_features(pkt):
    # 1) proto as string
    if pkt.haslayer(TCP):   p = 'tcp'
    elif pkt.haslayer(UDP): p = 'udp'
    elif pkt.haslayer(ARP): p = 'arp'
    else:                   p = 'icmp'
    proto = clamp(p, PROTO_CATS, FALLBACK_PROTO)

    # 2) service by port as string
    if pkt.haslayer(TCP):
        port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        port = pkt[UDP].dport
    else:
        port = 0

    if port == 80:
        s = 'http'
    elif port == 443:
        s = 'http_443'
    elif port == 53:
        s = 'domain'
    else:
        s = FALLBACK_SERVICE
    service = clamp(s, SERVICE_CATS, FALLBACK_SERVICE)

    # 3) conn_state as string (ACK → 'SF', else fallback)
    if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x10):
        c = 'SF'
    else:
        c = FALLBACK_CONN_STATE
    conn_state = clamp(c, STATE_CATS, FALLBACK_CONN_STATE)

    # 4) numeric features
    L = float(len(pkt))
    return {
        'proto':      proto,
        'service':    service,
        'duration':   0.0,
        'orig_bytes': L,
        'resp_bytes': 0.0,
        'conn_state': conn_state
    }

def predict(feats):
    df = pd.DataFrame([feats], columns=FEATURE_ORDER)
    p = pipe.predict_proba(df)[0,1]
    return p, p > THRESHOLD

def handle_packet(pkt):
    if IP in pkt:
        feats = packet_to_features(pkt)
        p, mal = predict(feats)
        ts = time.strftime("%H:%M:%S")
        status = "MALICIOUS" if mal else "benign"

        log_entry = (
            f"[{ts}] {pkt.summary()}\n"
            f"   Features: {feats}\n"
            f"   Score: {p:.3f} → {status}\n"
            + "-" * 40 + "\n"
        )

        print(log_entry.strip())  # Console output

        with open(LOG_FILE, "a") as f:  # Save to log file
            f.write(log_entry)

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "lo"
    print(f"Sniffing on {iface}")
    sniff(iface=iface, prn=handle_packet, store=False)
