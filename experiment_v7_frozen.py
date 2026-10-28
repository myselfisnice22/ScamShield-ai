"""ScamShield V7 research experiment.

Adds 600 *synthetic* training examples (300 scam, 300 legitimate), using
reproducible templates. Compares V4 and V7 only on the existing development
set. This is NOT a final or real-world accuracy evaluation.

Requires AI_Model.py, experiment_v3.py, experiment_v4.py, and evaluate_scams.py
in the same directory. No third-party libraries are needed.
"""

import csv
import random
from collections import Counter
from math import log
from pathlib import Path

from AI_Model import words
from experiment_v3 import v3_training
from experiment_v4 import predict_v4
from evaluate_scams import tests

SEED = 2026
EXAMPLES_PER_TEMPLATE = 15
OUTPUT_DIR = Path(__file__).resolve().parent

# Each category uses 20 message patterns. The labels describe the fictional
# scenario assumed by the author, not a fact proven from the text alone.
SCAM_TEMPLATES = [
    "Your {bank} account will be blocked in {deadline}. Enter your PIN at {site} to restore access.",
    "Your {bank} FICA check failed. Upload your identity documents through {site} immediately.",
    "Your {service} subscription is expiring. Confirm your password at {site} to stop suspension.",
    "Your {courier} parcel is held until you pay a handling charge of {amount} through {site}.",
    "You have won a {prize}. Send your {credential} to collect your reward.",
    "A refund of {amount} is waiting. Enter your card number and CVV on {site}.",
    "I am your {relative} using a new number. Transfer {amount} to this unfamiliar account now.",
    "Your {account_type} is locked. Share your {credential} with our support agent.",
    "Earn guaranteed {return_rate} returns if you invest {amount} in this cryptocurrency offer.",
    "Move your {bank} savings to a new safe account within {deadline} or your funds may be stolen.",
    "Your {utility} service will be disconnected in {deadline}. Pay this unknown beneficiary.",
    "To fix your {service} login, install {software} so the stranger can control your device.",
    "Your {employer} salary deposit cannot clear within {deadline} until you reveal your PIN and password.",
    "Your {event} bursary is approved. Send {amount} in advance to release the scholarship funds.",
    "A transfer from {bank} failed. Forward the OTP to our agent within {deadline}.",
    "Congratulations! Your {prize} is reserved. First pay {amount} for prize insurance.",
    "Your tax profile has been flagged. Update your banking credentials on {site} before {deadline}.",
    "Your {mobile_network} SIM will be terminated unless you send an ID copy to {site}.",
    "Pay {amount} to cancel an invented police fine or face arrest in {deadline}.",
    "Double your money by recruiting {friends} friends and paying {amount} to join.",
]

SAFE_TEMPLATES = [
    "Your {bank} statement for {period} is available in the official app. Do not share your PIN.",
    "Never reveal an OTP to someone who claims to work at {bank} and contacts you {contact_method}.",
    "The {event} at {school} begins on {day} at {time}.",
    "Please bring your {item} to {school} on {day}.",
    "Your {courier} delivery arrived and was left with reception at {place}.",
    "You can review your {service} renewal for {period} in the official settings page.",
    "Our workshop at {school} explains how fake {bank} links steal passwords.",
    "The coach moved {event} practice to {day} at {time}.",
    "Your appointment with the {person} is scheduled for {day} at {time}.",
    "There will be planned {utility} maintenance near {place} on {day}.",
    "A legitimate {bank} will never ask you to send your PIN or CVV {contact_method}.",
    "Congratulations on your result in the {event} competition at {school}.",
    "Please verify that your name is correct on the {document} by {day}.",
    "The teacher uploaded your {item} homework to the {school} portal.",
    "Our class presentation on {service} scams will be held on {day}.",
    "Dad will collect you from {school} at {time} on {day}.",
    "To change your {service} password on {day}, open the official app yourself.",
    "The {bank} website explains ways to protect your account from {threat}.",
    "A real {service} support representative should not request remote access to your {device}.",
    "Please ignore suspicious texts demanding {amount} to win a {prize}.",
]

OPTIONS = {
    "credential": ["banking details", "PIN", "card number", "account password", "card security code"],
    "account_type": ["digital wallet", "payment account", "banking account", "mobile wallet", "cryptocurrency account"],
    "software": ["a screen sharing tool", "an unverified app", "a remote desktop tool", "unknown software", "a control utility"],
    "employer": ["company", "contractor", "employer", "payroll", "workplace"],
    "mobile_network": ["mobile network", "phone operator", "SIM provider", "cellular service", "mobile service"],
    "period": ["January", "February", "March", "April", "May", "June"],
    "contact_method": ["by text", "on the phone", "over WhatsApp", "in an email", "via a chat message"],
    "threat": ["fraud", "phishing", "scams", "impostors", "identity theft"],
    "device": ["phone", "computer", "tablet", "laptop", "workstation"],
    "bank": ["bank", "savings bank", "credit union", "mobile bank", "banking service"],
    "deadline": ["15 minutes", "one hour", "two hours", "today", "24 hours"],
    "site": ["an unknown website", "this texted link", "an unfamiliar page", "a shortened link", "a verification page"],
    "service": ["streaming", "email", "shopping", "cloud storage", "mobile account"],
    "courier": ["courier", "parcel company", "delivery service", "shipping company", "local courier"],
    "amount": ["R50", "R125", "R300", "R850", "R2500", "R6000"],
    "prize": ["phone", "tablet", "cash prize", "holiday", "gift voucher"],
    "relative": ["aunt", "uncle", "cousin", "brother", "sister"],
    "return_rate": ["30 percent", "50 percent", "100 percent", "double", "triple"],
    "utility": ["electricity", "water", "internet", "municipal", "gas"],
    "friends": ["two", "three", "four", "five", "six"],
    "event": ["swimming", "coding", "science", "soccer", "tennis"],
    "school": ["school", "campus", "science club", "sports centre", "classroom"],
    "day": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
    "time": ["8 AM", "10 AM", "noon", "2 PM", "4 PM"],
    "item": ["maths", "technology", "science", "English", "geography"],
    "place": ["the office", "the library", "the main building", "the reception desk", "the community hall"],
    "person": ["dentist", "teacher", "coach", "doctor", "tutor"],
    "document": ["certificate", "permission form", "assignment", "report", "registration form"],
}


def normalise(message):
    return " ".join(message.lower().split())


def generate_examples():
    """Generate 600 unique labeled examples, deterministically."""
    rng = random.Random(SEED)
    output = []
    seen = set()

    for label, templates in (("scam", SCAM_TEMPLATES), ("safe", SAFE_TEMPLATES)):
        for template in templates:
            made = 0
            attempts = 0
            while made < EXAMPLES_PER_TEMPLATE:
                attempts += 1
                if attempts > 2000:
                    raise RuntimeError("Unable to generate distinct examples")
                values = {k: rng.choice(v) for k, v in OPTIONS.items()}
                message = template.format(**values)
                key = normalise(message)
                if key in seen:
                    continue
                seen.add(key)
                output.append((message, label))
                made += 1

    rng.shuffle(output)
    return output


def extract_features(message):
    tokens = words(message)  # Same tokenizer used by V4
    singles = ["W:" + token for token in tokens]
    pairs = ["B:" + tokens[i] + "_" + tokens[i + 1]
             for i in range(len(tokens) - 1)]
    return singles + pairs


class BigramNaiveBayes:
    """Same feature type and smoothing as the Version 4 experiment."""

    def __init__(self, training):
        self.labels = ("scam", "safe")
        self.doc_counts = Counter()
        self.feature_counts = {label: Counter() for label in self.labels}
        self.vocabulary = set()
        for message, label in training:
            feature_list = extract_features(message)
            self.doc_counts[label] += 1
            self.feature_counts[label].update(feature_list)
            self.vocabulary.update(feature_list)
        self.n = len(training)
        self.totals = {label: sum(self.feature_counts[label].values())
                       for label in self.labels}

    def predict(self, message):
        scores = {}
        for label in self.labels:
            score = log(self.doc_counts[label] / self.n)
            denominator = self.totals[label] + len(self.vocabulary) + 1
            for feature in extract_features(message):
                if feature not in self.vocabulary:
                    continue
                score += log((self.feature_counts[label][feature] + 1)
                             / denominator)
            scores[label] = score
        return max(scores, key=scores.get)


synthetic_examples = generate_examples()
v7_training = list(v3_training) + synthetic_examples
v7_model = BigramNaiveBayes(v7_training)


def predict_v7(message):
    return v7_model.predict(message)


def summary(name, answers):
    total = len(tests)
    correct = sum(guess == actual for (_, actual), guess in zip(tests, answers))
    missed = sum(actual == "scam" and guess == "safe"
                 for (_, actual), guess in zip(tests, answers))
    false_alarms = sum(actual == "safe" and guess == "scam"
                       for (_, actual), guess in zip(tests, answers))
    scams = sum(label == "scam" for _, label in tests)
    accuracy = 100 * correct / total
    recall = 100 * (scams - missed) / scams
    print(f"\n{name}")
    print(f"Accuracy: {accuracy:.1f}% ({correct}/{total})")
    print(f"Missed scams: {missed}")
    print(f"False alarms: {false_alarms}")
    print(f"Scam recall: {recall:.1f}%")
    return accuracy


def main():
    assert len(SCAM_TEMPLATES) == len(SAFE_TEMPLATES) == 20
    assert len(synthetic_examples) == 600
    assert Counter(label for _, label in synthetic_examples) == {
        "scam": 300, "safe": 300
    }

    # Never train on exact duplicate development examples.
    train_set = {normalise(m) for m, _ in v7_training}
    dev_set = {normalise(m) for m, _ in tests}
    overlap = train_set & dev_set
    if overlap:
        raise ValueError(f"Training/development duplicate found: {sorted(overlap)[0]}")

    with (OUTPUT_DIR / "v7_synthetic_training.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.writer(f)
        writer.writerow(["message", "label", "origin"])
        for message, label in synthetic_examples:
            writer.writerow([message, label, "synthetic_template"])

    v4 = [predict_v4(message) for message, _ in tests]
    v7 = [predict_v7(message) for message, _ in tests]

    print("SCAMSHIELD AI V7 - DEVELOPMENT EXPERIMENT")
    print("600 synthetic examples + original V3 training messages")
    print("No exact training/development duplicates detected.")
    a4 = summary("V4 baseline", v4)
    a7 = summary("V7 larger training dataset", v7)
    print(f"\nDevelopment accuracy change: {a7 - a4:+.1f} percentage points")

    with (OUTPUT_DIR / "v7_development_predictions.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        writer = csv.writer(f)
        writer.writerow(["message", "actual", "v4", "v7"])
        for (message, actual), p4, p7 in zip(tests, v4, v7):
            writer.writerow([message, actual, p4, p7])

    print("\nNew files:")
    print("  v7_synthetic_training.csv")
    print("  v7_development_predictions.csv")
    print("\nResearch note: Synthetic messages and reused development tests")
    print("cannot establish independent real-world detection accuracy.")
    print("Do NOT evaluate or tune against the final holdout yet.")


if __name__ == "__main__":
    main()
