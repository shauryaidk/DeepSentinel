from collections import Counter
import math


def shannon_entropy(values):
    values = list(values)
    if not values:
        return 0.0

    counts = Counter(values)
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalized_entropy(values):
    values = list(values)
    distinct = len(set(values))
    if len(values) < 2 or distinct <= 1:
        return 0.0
    h = shannon_entropy(values)
    return h / math.log2(distinct)
