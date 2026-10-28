from collections import Counter
from math import log

from AI_Model import training_data, words, predict
from evaluate_scams import tests

# =========================================
# SCAMSHIELD AI - VERSION 3 EXPERIMENT
# Hypothesis: More varied training data
# will improve detection performance.
# =========================================

# NEW TRAINING EXAMPLES
# These are separate from our 60 test messages.

new_examples = [
    # SCAM EXAMPLES
    ("We recorded private footage pay money to stop its release", "scam"),
    ("Transfer money or we will publish your private information", "scam"),
    ("Enter card details to receive your tax refund", "scam"),
    ("Pay an administration fee to receive your inheritance", "scam"),
    ("A recruiter demands payment before offering a job", "scam"),
    ("Your online wallet is locked transfer funds to restore access", "scam"),
    ("Give us your login code to recover your profile", "scam"),
    ("Your delivery failed pay a handling charge now", "scam"),
    ("A stranger promises to double your investment overnight", "scam"),
    ("An unknown person claims to be your relative and requests cash", "scam"),
    ("Reveal your card security digits to collect a bonus", "scam"),
    ("A support agent demands remote access to your computer", "scam"),
    ("Your account will close unless you provide private credentials", "scam"),
    ("Claim a scholarship after paying an advance deposit", "scam"),
    ("Send your identity documents to an unverified website", "scam"),

    # LEGITIMATE EXAMPLES
    ("Never share your password with strangers", "safe"),
    ("Keep your OTP and PIN private", "safe"),
    ("Our teacher warned us about fake banking messages", "safe"),
    ("Congratulations on your science achievement", "safe"),
    ("The bank advises customers to protect their card numbers", "safe"),
    ("Reset your password using the official application", "safe"),
    ("The school is hosting an online fraud awareness lesson", "safe"),
    ("Please submit your homework before Friday", "safe"),
    ("Your package is waiting at the reception desk", "safe"),
    ("Do not transfer money to suspicious strangers", "safe"),
    ("Your phone provider explains how to secure your SIM", "safe"),
    ("Check whether a website is genuine before signing in", "safe"),
    ("The coach confirmed our swimming competition", "safe"),
    ("Please verify your name on the examination paper", "safe"),
    ("Your security awareness workshop starts tomorrow", "safe")
]

# Combine original training data with new examples.
v3_training = training_data + new_examples

labels = ["scam", "safe"]
counts = {label: Counter() for label in labels}
message_counts = Counter()
vocabulary = set()

# TRAIN THE UPDATED MODEL

for message, label in v3_training:
    tokens = words(message)

    counts[label].update(tokens)
    message_counts[label] += 1
    vocabulary.update(tokens)


def predict_v3(message):
    scores = {}

    for label in labels:
        scores[label] = log(
            message_counts[label] / len(v3_training)
        )

        total = sum(counts[label].values())

        for word in words(message):

            if word not in vocabulary:
                continue

            probability = (
                (counts[label][word] + 1)
                / (total + len(vocabulary) + 1)
            )

            scores[label] += log(probability)

    return max(scores, key=scores.get)


# =========================================
# EVALUATION
# =========================================

def evaluate(model, name):
    correct = 0
    missed_scams = 0
    false_alarms = 0
    caught_scams = 0

    print("\n==========================")
    print(name)
    print("==========================")

    for message, expected in tests:
        result = model(message)

        if result == expected:
            correct += 1
        else:
            print("\nFAILED:", message)
            print("Expected:", expected)
            print("Predicted:", result)

        if expected == "scam":
            if result == "scam":
                caught_scams += 1
            else:
                missed_scams += 1

        if expected == "safe" and result == "scam":
            false_alarms += 1

    accuracy = correct / len(tests) * 100
    recall = caught_scams / 30 * 100

    print("\nFINAL RESULTS")
    print(f"Accuracy: {accuracy:.1f}%")
    print(f"Correct: {correct}/{len(tests)}")
    print(f"Missed scams: {missed_scams}")
    print(f"False alarms: {false_alarms}")
    print(f"Scam recall: {recall:.1f}%")

    return accuracy


if __name__ == "__main__":

    print("SCAMSHIELD RESEARCH EXPERIMENT 3")

    assert len(tests) == 60

    old_accuracy = evaluate(
        predict,
        "VERSION 2.0"
    )

    new_accuracy = evaluate(
        predict_v3,
        "VERSION 3.0"
    )

    print("\n==========================")
    print("VERSION COMPARISON")
    print("==========================")

    print(f"Version 2: {old_accuracy:.1f}%")
    print(f"Version 3: {new_accuracy:.1f}%")

    change = new_accuracy - old_accuracy

    print(f"Change: {change:+.1f} percentage points")
    print("\nExperiment complete!")
    print("Development data only, not final accuracy.")
