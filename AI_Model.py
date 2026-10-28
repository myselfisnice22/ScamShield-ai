
from collections import Counter
from math import log
import re

# =====================================
# SCAMSHIELD AI - VERSION 2.0
# MACHINE LEARNING SCAM DETECTOR
# =====================================

print("ScamShield AI model loaded!")

# STEP 1: Training data

training_data = [
    ("urgent verify your bank account immediately", "scam"),
    ("click here to reset your password", "scam"),
    ("you won a cash prize claim now", "scam"),
    ("send your otp to unlock your account", "scam"),
    ("pay a delivery fee to release your parcel", "scam"),
    ("confirm your banking details or get suspended", "scam"),

    ("see you at school tomorrow", "safe"),
    ("please bring your homework", "safe"),
    ("swimming practice starts this afternoon", "safe"),
    ("your appointment is confirmed", "safe"),
    ("can you call me after dinner", "safe"),
    ("happy birthday have a great day", "safe")
]

# STEP 2: Prepare the learning system

labels = ["scam", "safe"]

word_counts = {
    label: Counter() for label in labels
}

message_counts = Counter()
vocabulary = set()


def words(text):
    return re.findall(r"[a-z]+", text.lower())


# STEP 3: Train the AI model

for message, label in training_data:
    tokens = words(message)

    word_counts[label].update(tokens)
    message_counts[label] += 1
    vocabulary.update(tokens)


# STEP 4: Predict whether a message is a scam

def predict(message):
    scores = {}

    for label in labels:

        scores[label] = log(
            message_counts[label] / len(training_data)
        )

        total = sum(word_counts[label].values())

        for word in words(message):

            # NEW: Ignore words not seen during training
            if word not in vocabulary:
                continue

            probability = (
                (word_counts[label][word] + 1)
                / (total + len(vocabulary) + 1)
            )

            scores[label] += log(probability)

    return max(scores, key=scores.get)


# STEP 5: Run ScamShield AI

if __name__ == "__main__":

    print("\n==========================")
    print("SCAMSHIELD AI - VERSION 2.0")
    print("Machine Learning Detector")
    print("==========================")

    message = input("\nEnter a message to scan: ")

    result = predict(message)

    print("\nSCAN RESULTS")
    print("--------------------------")

    if result == "scam":
        print("HIGH RISK - Possible scam!")

    else:
        print("No known scam pattern detected.")

    print("AI Prediction:", result.upper())
    print("Experimental prediction - not proof of safety.")

    print("\nScan completed!")
