from collections import Counter
from math import log
import csv

from AI_Model import words
from experiment_v3 import v3_training, predict_v3
from evaluate_scams import tests

# =======================================
# SCAMSHIELD AI - VERSION 4.0
# WORDS + TWO-WORD PHRASES
# =======================================

print("\nSCAMSHIELD AI - EXPERIMENT 4")

labels = ["scam", "safe"]

# STEP 1 - Extract words and two-word phrases

def extract_features(message):
    tokens = words(message)

    single_words = [
        "W:" + word for word in tokens
    ]

    two_word_phrases = [
        "B:" + tokens[i] + "_" + tokens[i + 1]
        for i in range(len(tokens) - 1)
    ]

    return single_words + two_word_phrases


# STEP 2 - Train using Version 3's data

feature_counts = {
    label: Counter() for label in labels
}

message_counts = Counter()
vocabulary = set()

for message, label in v3_training:
    features = extract_features(message)

    feature_counts[label].update(features)
    message_counts[label] += 1
    vocabulary.update(features)


# STEP 3 - Make predictions

def predict_v4(message):
    scores = {}

    for label in labels:

        scores[label] = log(
            message_counts[label] / len(v3_training)
        )

        total = sum(feature_counts[label].values())

        for feature in extract_features(message):

            if feature not in vocabulary:
                continue

            probability = (
                (feature_counts[label][feature] + 1)
                / (total + len(vocabulary) + 1)
            )

            scores[label] += log(probability)

    return max(scores, key=scores.get)


# STEP 4 - Measure accuracy and mistakes

def evaluate(name, predictions):

    correct = 0
    missed_scams = 0
    false_alarms = 0
    detected_scams = 0

    for (message, expected), prediction in zip(
        tests, predictions
    ):

        if prediction == expected:
            correct += 1

        if expected == "scam":
            if prediction == "scam":
                detected_scams += 1
            else:
                missed_scams += 1

        elif prediction == "scam":
            false_alarms += 1

    accuracy = correct / len(tests) * 100

    recall = detected_scams / 30 * 100

    print("\n============================")
    print(name)
    print("============================")
    print(f"Accuracy: {accuracy:.1f}%")
    print(f"Correct: {correct}/{len(tests)}")
    print(f"Missed scams: {missed_scams}")
    print(f"False alarms: {false_alarms}")
    print(f"Scam recall: {recall:.1f}%")

    return accuracy


# STEP 5 - Compare Version 3 and Version 4

if __name__ == "__main__":

    assert len(tests) == 60

    v3_predictions = [
        predict_v3(message)
        for message, expected in tests
    ]

    v4_predictions = [
        predict_v4(message)
        for message, expected in tests
    ]

    accuracy_v3 = evaluate(
        "VERSION 3.0", v3_predictions
    )

    accuracy_v4 = evaluate(
        "VERSION 4.0", v4_predictions
    )

    print("\n============================")
    print("RESEARCH COMPARISON")
    print("============================")

    print(f"Version 3: {accuracy_v3:.1f}%")
    print(f"Version 4: {accuracy_v4:.1f}%")

    difference = accuracy_v4 - accuracy_v3

    print(
        f"Improvement: {difference:+.1f} percentage points"
    )

    print("\nMESSAGES FIXED BY VERSION 4:")

    for (message, expected), old, new in zip(
        tests, v3_predictions, v4_predictions
    ):
        if old != expected and new == expected:
            print("-", message)

    print("\nNEW MISTAKES IN VERSION 4:")

    for (message, expected), old, new in zip(
        tests, v3_predictions, v4_predictions
    ):
        if old == expected and new != expected:
            print("-", message)

    # Save research results to a CSV file

    with open(
        "scamshield_v4_results.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Message",
            "Actual Label",
            "Version 3 Prediction",
            "Version 4 Prediction"
        ])

        for (message, expected), old, new in zip(
            tests, v3_predictions, v4_predictions
        ):
            writer.writerow([
                message, expected, old, new
            ])

    print("\nResearch results saved!")
    print("\nVERSION 4 - MISSED SCAMS")
    print("==========================")

    missed = 0

    for (message, expected), prediction in zip(
        tests, v4_predictions
    ):
        if expected == "scam" and prediction == "safe":
            missed += 1
            print(f"{missed}. {message}")

    print("\nTotal missed scams:", missed)
    print("File: scamshield_v4_results.csv")
    print("These are development results only.")


