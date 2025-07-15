import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import os

def load_suricata_rules(rule_path="/app/rules/suricata.rules"):
    """
    Loads Suricata rules and extracts the 'content' part to build a behavior model.
    """
    print(f"[BehaviorModel] Attempting to load rules from: {rule_path}")
    rules = []
    if not os.path.exists(rule_path):
        print(f"[BehaviorModel] Rule file not found: {rule_path}")
        return []
    with open(rule_path, 'r') as f:
        for line in f:
            if line.startswith('alert'):
                content_match = re.search(r'content:"([^"]+)"', line)
                if content_match:
                    rules.append(content_match.group(1))
    print(f"[BehaviorModel] Loaded {len(rules)} Suricata rules.")
    return rules

class BehaviorModel:
    def __init__(self, rules):
        print("[BehaviorModel] Initializing BehaviorModel...")
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3))
        if rules:
            self.rule_vectors = self.vectorizer.fit_transform(rules)
            print(f"[BehaviorModel] Vectorized {self.rule_vectors.shape[0]} rules.")
        else:
            self.rule_vectors = None
            print("[BehaviorModel] No rules provided, behavior model will return 0.0 similarity.")

    def get_similarity(self, packet_content):
        """
        Calculates the maximum similarity between a packet's content and the Suricata rules.
        """
        if self.rule_vectors is None or self.rule_vectors.shape[0] == 0:
            return 0.0

        packet_vector = self.vectorizer.transform([packet_content])
        similarities = cosine_similarity(packet_vector, self.rule_vectors)
        return similarities.max()

# Load rules and initialize the model globally
print("[BehaviorModel] Loading Suricata rules for global model...")
suricata_rules = load_suricata_rules()
behavior_model = BehaviorModel(suricata_rules)
print("[BehaviorModel] Global behavior_model initialized.")