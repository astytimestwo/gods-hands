import os
import json
import logging
import threading
from pathlib import Path
from typing import Callable, Optional, Dict, Any

try:
    import requests
except ImportError:
    requests = None

try:
    from llama_cpp import Llama
except ImportError:
    Llama = None

logger = logging.getLogger(__name__)

class AIInstaller:
    """Manages the downloading of the SmolLM2 model."""
    
    # HuggingFace repository for SmolLM2 135M instruct
    MODEL_URL = "https://huggingface.co/lmstudio-community/SmolLM2-135M-Instruct-GGUF/resolve/main/SmolLM2-135M-Instruct-Q4_K_M.gguf"
    MODEL_DIR = Path(os.path.abspath("models"))
    MODEL_PATH = MODEL_DIR / "SmolLM2-135M-Instruct-Q4_K_M.gguf"

    @classmethod
    def get_status(cls) -> str:
        """Returns 'installed', 'missing', or 'unavailable'."""
        if requests is None:
            return "unavailable" # missing requests library
        if cls.MODEL_PATH.exists():
            # Check the size roughly (should be ~93MB for Q4)
            if cls.MODEL_PATH.stat().st_size > 50 * 1024 * 1024:
                # Need llama_cpp to actually run it
                if Llama is None:
                    return "unavailable_no_llama"
                return "installed"
            else:
                # Corrupted or partial download
                return "missing"
        return "missing"

    @classmethod
    def download(cls, progress_callback: Callable[[float], None]) -> bool:
        """Downloads the model, reporting progress via callback (0.0 to 1.0)."""
        cls.MODEL_DIR.mkdir(exist_ok=True)
        
        try:
            response = requests.get(cls.MODEL_URL, stream=True, timeout=10)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            block_size = 1024 * 1024 # 1MB
            downloaded = 0
            
            with open(cls.MODEL_PATH, 'wb') as f:
                for data in response.iter_content(block_size):
                    f.write(data)
                    downloaded += len(data)
                    if total_size > 0:
                        progress = downloaded / total_size
                        progress_callback(progress)
            
            progress_callback(1.0)
            return True
        except Exception as e:
            logger.error(f"Download failed: {e}")
            if cls.MODEL_PATH.exists():
                cls.MODEL_PATH.unlink() # Cleanup failed download
            progress_callback(-1.0) # Signal error
            return False

class Intelligence:
    """Orchestrates the LLM for natural language processing."""
    
    def __init__(self):
        self._llm = None
        self._lock = threading.Lock()
        
    def initialize(self):
        """Loads the model into memory. Returns True if successful."""
        with self._lock:
            if self._llm is not None:
                return True
                
            if AIInstaller.get_status() != "installed":
                return False
                
            try:
                # Very low context window and constraints for lightweight memory
                self._llm = Llama(
                    model_path=str(AIInstaller.MODEL_PATH),
                    n_ctx=1024,      
                    n_threads=4,     
                    verbose=False    
                )
                return True
            except Exception as e:
                logger.error(f"Failed to load LLM: {e}")
                return False
                
    def process_input(self, text: str) -> Dict[str, Any]:
        """
        Takes raw user intent, feeds it to the LLM, and forces JSON output.
        Returns: {
            "response": "The natural language response",
            "intent": null or {"action": "lock", "args": {"name": "secret", "minutes": 10, "secret": "abc"}} / {"action": "reveal", "args": {"name": "secret"}}
        }
        """
        if self._llm is None:
            if not self.initialize():
                return {"response": "My intelligence is currently dormant. Use slash commands like /lock.", "intent": None}

        intent = None
        lower_text = text.lower()
        
        # Heuristic NLP for command execution
        if "lock" in lower_text or "seal" in lower_text:
            if "minute" in lower_text or "min" in lower_text:
                import re
                min_match = re.search(r'(\d+)\s*m', lower_text)
                minutes = int(min_match.group(1)) if min_match else 10
                
                # Attempt to extract secret and name intelligently
                extracted_secret = text
                if "secret is" in lower_text:
                    extracted_secret = text[lower_text.find("secret is") + 9:].strip()
                elif "the secret is" in lower_text:
                    extracted_secret = text[lower_text.find("the secret is") + 13:].strip()
                
                name_match = re.search(r'(?:seal|lock)\s+(.*?)\s+for', lower_text)
                extracted_name = name_match.group(1).strip() if name_match else f"fate_{minutes}"
                if len(extracted_name) > 20: extracted_name = f"fate_{minutes}"
                
                intent = {"action": "lock", "args": {"name": extracted_name, "minutes": minutes, "secret": extracted_secret}}
        
        if "show" in lower_text or "list" in lower_text or "vault" in lower_text:
            intent = {"action": "list", "args": {}}
        elif "reveal" in lower_text or "open" in lower_text:
            import re
            name_match = re.search(r'(?:reveal|open)\s+(.*?)(?:$|\.)', lower_text)
            extracted_name = name_match.group(1).strip() if name_match else ""
            if extracted_name:
                intent = {"action": "reveal", "args": {"name": extracted_name}}

        # Few-Shot Prompting: We provide perfectly formatted past "conversations" 
        # to force the 135M model into the correct stylistic pattern.
        prompt = (
            "<|im_start|>system\nYou are the God of the Vault. You speak in exactly one short, mysterious phrase. No parentheses, no actions, no quotes.<|im_end|>\n"
            "<|im_start|>user\nWho are you?<|im_end|>\n"
            "<|im_start|>assistant\nI am the keeper of forgotten fates.<|im_end|>\n"
            "<|im_start|>user\nWhat is your purpose?<|im_end|>\n"
            "<|im_start|>assistant\nTo seal that which mortals cannot bear to hold.<|im_end|>\n"
            "<|im_start|>user\nCan you hear me?<|im_end|>\n"
            "<|im_start|>assistant\nYour whispers echo in the void.<|im_end|>\n"
            f"<|im_start|>user\n{text}<|im_end|>\n"
            "<|im_start|>assistant\n"
        )

        try:
            with self._lock:
                output = self._llm(
                    prompt,
                    max_tokens=24,  # Heavily restrict verbosity
                    stop=["<|im_end|>", "\n", "User:", "Assistant:"],
                    temperature=0.3, # Low temperature for consistency
                    repeat_penalty=1.2
                )
                
            raw_text = output['choices'][0]['text'].strip()
            
            # --- Aggressive Post-Processing ---
            import re
            
            # Remove parenthetical stage directions e.g. (He smiles ominously)
            cleaned = re.sub(r'\([^)]*\)', '', raw_text)
            cleaned = re.sub(r'\[[^\]]*\]', '', cleaned)
            
            # Remove rogue prefixes
            prefixes = ["God:", "God of the Vault:", "Response:", "Assistant:"]
            for p in prefixes:
                if cleaned.startswith(p):
                    cleaned = cleaned[len(p):]
                    
            # Strip quotes and extra spaces
            cleaned = cleaned.replace('"', '').replace('`', '').strip()
            
            # Truncate at first sentence using basic heuristics
            sentences = re.split(r'(?<=[.!?]) +', cleaned)
            if sentences:
                cleaned = sentences[0]
                
            # If the LLM completely failed or output code/jargon
            if len(cleaned) < 2 or "import " in cleaned or "def " in cleaned or "```" in cleaned:
                cleaned = "The void does not answer."

            # Hardcode specific overrides for the action intents to guarantee 0 jargon on operations
            if intent and intent["action"] == "lock":
                cleaned = "Your fate is now sealed within the vault."
            elif intent and intent["action"] == "reveal":
                cleaned = "Let us see if the time has come to reveal this."
            elif intent and intent["action"] == "list":
                cleaned = "I shall consult the destiny threads."

            return {"response": cleaned, "intent": intent}

            

        except Exception as e:
            return {"response": f"My connection fades... ({str(e)})", "intent": None}
