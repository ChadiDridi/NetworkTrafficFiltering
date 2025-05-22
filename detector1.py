#!/home/chadi/anaconda3/envs/furrsah38/bin/python
import sys
import time
import pandas as pd
import joblib
from scapy.all import sniff, IP, TCP, UDP

# Configuration
MODEL_PATH   = "model_5_pipeline.pkl"
FEATURE_ORDER = [
    'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
    'conn_state', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes'
]
THRESHOLD    = 0.65

# Load pipeline (includes encoders inside)
pipe = joblib.load(MODEL_PATH)
print("✅ Pipeline loaded.")

# Packet → features, raw strings and numeric features as in training
def packet_to_features(pkt):
    # Determine protocol string lowercase
    if TCP in pkt:
        proto = 'tcp'
    elif UDP in pkt:
        proto = 'udp'
    elif pkt.haslayer('ARP'):
        proto = 'arp'
    else:
        proto = 'other'

    # Determine service based on destination port (lowercase)
    if TCP in pkt:
        dport = pkt[TCP].dport
    elif UDP in pkt:
        dport = pkt[UDP].dport
    else:
        dport = 0

    if dport == 80:
        service = 'http'
    elif dport == 443:
        service = 'https'
    elif dport == 53:
        service = 'dns'
    else:
        service = 'unknown'

    # conn_state default (as in training data)
    conn_state = 'sf'

    # Build feature dict
    feats = {
        'proto': proto,
        'service': service,
        'duration': 0.0,  # single packet
        'orig_bytes': float(len(pkt)),
        'resp_bytes': 0.0,
        'conn_state': conn_state,
        'orig_pkts': 1,
        'orig_ip_bytes': float(len(pkt)),
        'resp_pkts': 0,
        'resp_ip_bytes': 0
    }
    return feats

# Predict
def predict(feats):
    df = pd.DataFrame([feats], columns=FEATURE_ORDER)
    prob = pipe.predict_proba(df)[0,1]
    return prob, prob > THRESHOLD

# Packet handler
def handle_packet(pkt):
    if IP in pkt:
        feats = packet_to_features(pkt)
        score, mal = predict(feats)
        print("   Features:", feats)     
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {pkt.summary()}")
        print(f"   Score: {score:.3f} → {'MALICIOUS' if mal else 'benign'}")
        print("-" * 40)

if __name__ == "__main__":
    iface = sys.argv[1] if len(sys.argv) > 1 else "lo"
    print(f"🚀 Sniffing on {iface}")
    sniff(iface=iface, prn=handle_packet, store=False)
