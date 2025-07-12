
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

def load_suricata_rules(rule_path="rules/suricata.rules"):
    """
    Loads Suricata rules and extracts the 'content' part to build a behavior model.
    """
    rules = []
    with open(rule_path, 'r') as f:
        for line in f:
            if line.startswith('alert'):
                content_match = re.search(r'content:"([^"]+)"', line)
                if content_match:
                    rules.append(content_match.group(1))
    return rules

class BehaviorModel:
    def __init__(self, rules):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 3))
        if rules:
            self.rule_vectors = self.vectorizer.fit_transform(rules)
        else:
            self.rule_vectors = None

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
suricata_rules = load_suricata_rules()
behavior_model = BehaviorModel(suricata_rules)
