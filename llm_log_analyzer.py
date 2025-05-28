import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import textwrap
import re
import logging
import gc
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
HF_TOKEN = "insert a token here from hugging face (free :=) "  #read me !

def load_model():
    """Load model with error handling"""
    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        tokenizer.pad_token = tokenizer.eos_token  # Set pad token
        
        model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            device_map="auto",
            torch_dtype=torch.float32
        )
        logger.info("Model loaded successfully")
        return model, tokenizer
    except Exception as e:
        logger.error(f"Model loading failed: {str(e)}")
        return None, None

def extract_log_features(log_text):
    """Robust log feature extraction with diagnostics"""
    features = []
    total_lines = len(log_text.splitlines())
    logger.info(f"Processing {total_lines} log lines")
    
    # Enhanced pattern to handle variations
    pattern = r"Features: ({.*?})\s+Score: ([\d.]+) → (\w+)"
    
    matches = list(re.finditer(pattern, log_text))
    logger.info(f"Found {len(matches)} potential log entries")
    
    for i, match in enumerate(matches):
        try:
            # Extract features string
            features_str = match.group(1)
            score = match.group(2)
            verdict = match.group(3)
            
            # Clean and convert to JSON format
            features_str = features_str.replace("'", "\"")
            features_str = features_str.replace("True", "true").replace("False", "false")
            
            # Parse with JSON
            feature_dict = json.loads(features_str)
            
            features.append({
                "score": float(score),
                "verdict": verdict,
                **feature_dict
            })
            logger.debug(f"Processed entry {i+1} successfully")
            
        except Exception as e:
            logger.warning(f"Error processing entry {i+1}: {str(e)}")
    
    logger.info(f"Successfully processed {len(features)}/{len(matches)} log entries")
    return features

def analyze_logs(model, tokenizer, log_text):
    """Simplified analysis with attention mask fix"""
    try:
        logger.info("Starting log analysis")
        
        # Parse features
        features = extract_log_features(log_text)
        if not features:
            logger.error("No features extracted - using placeholder analysis")
            return (
                "1. DDoS: No\n"
                "2. Predictions: Check log format\n"
                "3. Malicious: Unknown\n"
                "\nNote: Failed to parse log features"
            )
        
        # Create simple summary
        summary = (
            f"Found {len(features)} log entries. "
            f"Protocols: {', '.join(set(f['proto'] for f in features))}. "
            f"Avg score: {sum(f['score'] for f in features)/len(features):.3f}"
        )
        
        # Generate prompt
        prompt = (
            "Answer these questions based on network logs:\n"
            "1. Could this be a DDoS attack? (Yes/No)\n"
            "2. Are the predictions reasonable? (Yes/No/Maybe)\n"
            "3. Are any packets malicious? (Yes/No)\n\n"
            f"Log summary: {summary}\n\n"
            "Answers:"
        )
        
        logger.debug(f"Prompt: {prompt}")
        
        # Tokenize with attention mask
        inputs = tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True,
            return_attention_mask=True  # Critical fix
        )
        
        # Generate with attention mask
        outputs = model.generate(
            input_ids=inputs.input_ids,
            attention_mask=inputs.attention_mask,  
            max_new_tokens=100,
            num_beams=1,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id
        )
        
        # Extract response
        full_response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        response = full_response.replace(prompt, "").strip()
        return response
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        return "Analysis error"

def main():
    logger.info("Starting security analysis system")
    
    try:
        model, tokenizer = load_model()
        if model is None:
            return
        
        # Read log file with diagnostics
        try:
            logger.info("Reading log file...")
            with open("logs.txt", "r", encoding="utf-8") as f:
                log_text = f.read()
                
            logger.info("Sample log content:")
            sample_lines = log_text.splitlines()[:3]
            for line in sample_lines:
                logger.info(line)
                
            if not log_text.strip():
                logger.error("Log file is empty")
                return
        except Exception as e:
            logger.error(f"Failed to read log file: {str(e)}")
            return
        
        logger.info("Analyzing logs...")
        analysis = analyze_logs(model, tokenizer, log_text)
        
        # Print and save results
        print("\n" + "="*40)
        print("SECURITY ANALYSIS REPORT")
        print("="*40)
        print(analysis)
        print("="*40)
        
        with open("security_analysis.txt", "w", encoding="utf-8") as f:
            f.write("SECURITY ANALYSIS REPORT\n")
            f.write("="*40 + "\n")
            f.write(analysis)
        
        logger.info("Report saved to security_analysis.txt")
        
    except Exception as e:
        logger.error(f"Critical failure: {str(e)}")
    finally:
        gc.collect()
        logger.info("System shutdown")

if __name__ == "__main__":
    main()
