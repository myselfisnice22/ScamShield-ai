"""ScamShield V5: educational, pure-Python TF-IDF + logistic regression.
Uses only Python's standard library, avoiding scipy/scikit-learn DLLs.
Same V3 training data and development tests as prior versions.
"""

from collections import Counter
from math import exp, log, sqrt
import re

from experiment_v3 import v3_training, predict_v3
from experiment_v4 import predict_v4
from evaluate_scams import tests


def features(message):
    tokens = re.findall(r"[a-z0-9]+", message.lower())
    bigrams = [tokens[i] + "_" + tokens[i + 1]
               for i in range(len(tokens) - 1)]
    return tokens + bigrams


# Calculate inverse document frequency from TRAINING messages only.
train_counts = [Counter(features(message)) for message, _ in v3_training]
doc_freq = Counter(term for doc in train_counts for term in doc)
num_docs = len(v3_training)
idf = {term: log((1 + num_docs) / (1 + count)) + 1
       for term, count in doc_freq.items()}


def tfidf(message):
    counts = Counter(features(message))
    vector = {term: count * idf[term]
              for term, count in counts.items() if term in idf}
    norm = sqrt(sum(value * value for value in vector.values()))
    return {term: value / norm for term, value in vector.items()} if norm else {}


train_vectors = [tfidf(message) for message, _ in v3_training]
train_targets = [1 if label == "scam" else 0 for _, label in v3_training]
weights = {term: 0.0 for term in idf}
bias = 0.0


def sigmoid(z):
    # Numerically stable sigmoid.
    if z >= 0:
        return 1 / (1 + exp(-z))
    value = exp(z)
    return value / (1 + value)


# Fit a logistic-regression classifier with batch gradient descent.
learning_rate = 2.0
regularization = 0.002
for epoch in range(700):
    gradients = Counter()
    bias_gradient = 0.0
    for vector, target in zip(train_vectors, train_targets):
        score = bias + sum(weights[term] * value
                           for term, value in vector.items())
        error = sigmoid(score) - target
        bias_gradient += error
        for term, value in vector.items():
            gradients[term] += error * value

    for term in weights:
        gradient = gradients[term] / num_docs + regularization * weights[term]
        weights[term] -= learning_rate * gradient
    bias -= learning_rate * bias_gradient / num_docs


def predict_v5(message):
    vector = tfidf(message)
    score = bias + sum(weights[term] * value
                       for term, value in vector.items())
    return "scam" if sigmoid(score) >= 0.5 else "safe"


def evaluate(name, predictor):
    correct = missed = alarms = caught = 0
    for message, expected in tests:
        result = predictor(message)
        correct += result == expected
        if expected == "scam":
            caught += result == "scam"
            missed += result == "safe"
        else:
            alarms += result == "scam"

    print(f"\n{name}")
    print(f"Accuracy: {correct / len(tests) * 100:.1f}% ({correct}/{len(tests)})")
    print(f"Missed scams: {missed}")
    print(f"False alarms: {alarms}")
    scam_total = sum(expected == "scam" for _, expected in tests)
    print(f"Scam recall: {caught / scam_total * 100:.1f}%")


if __name__ == "__main__":
    print("SCAMSHIELD - VERSION 5 (PURE PYTHON)")
    evaluate("Version 3", predict_v3)
    evaluate("Version 4", predict_v4)
    evaluate("Version 5 - TF-IDF + Logistic Regression", predict_v5)
    print("\nVersion 5 missed scams:")
    for message, label in tests:
        if label == "scam" and predict_v5(message) == "safe":
            print("-", message)
    print("\nDevelopment dataset only, not real-world accuracy.")
