from transformers import pipeline
import os

os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
MODEL_PATH = "/home/chadi/.cache/huggingface/hub/models--google--flan-t5-small/snapshots/0fc9ddf78a1e988dac52e2dac162b0ede4fd74ab"

llm = pipeline(
    "text2text-generation",
    model=MODEL_PATH,
    max_length=500,
    do_sample=False,
)

def read_recent_logs(filepath="logs.txt", n_lines=40):
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()[-n_lines:]
        return "".join(lines)
    except FileNotFoundError:
        return "No logs found."

def analyze_logs():
    log_text = read_recent_logs()
    if len(log_text) > 250:
        log_text = log_text[-250:]

    # Explanation added
    field_explanation = (
        "Explanation of Fields:\n"
        "- proto: protocol used (e.g., tcp/udp)\n"
        "- service: application layer service\n"
        "- duration: connection duration in seconds\n"
        "- orig_bytes: bytes sent from originator\n"
        "- resp_bytes: bytes sent in response\n"
        "- conn_state: connection state (e.g., OTH means no response)\n"
        "- orig_pkts: packets sent by originator\n"
        "- orig_ip_bytes: total IP bytes sent from originator\n"
        "- resp_pkts: response packets\n"
        "- resp_ip_bytes: IP bytes sent in response\n"
        "- Score: model prediction score (closer to 1 = more malicious)\n"
    )

    prompt = (
        "Instruction: You are a network security assistant.\n"
        f"{field_explanation}"
        "Analyze the following packet logs and model predictions.\n"
        f"Logs:\n{log_text}\n"
        "Questions:\n"
        "1. Is this consistent with a DDoS attack?\n"
        "2. Are the predictions correct?\n"
        "3. Explain the packet if it's malicious.\n"
        "Answer the 3 questions clearly.\n"
    )

    result = llm(prompt)
    print("LLM Analysis:\n", result[0].get("generated_text") or result[0].get("text"))

if __name__ == "__main__":
    analyze_logs()
