import math
from collections import Counter

def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy: H(X) = -sum(P(x) * log2(P(x)))."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())