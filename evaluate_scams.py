from math import log
from AI_Model import (
    predict,
    training_data,
    labels,
    word_counts,
    message_counts,
    vocabulary,
    words
)

# ==========================================
# SCAMSHIELD AI - RESEARCH EXPERIMENT 2
# Version 1 vs Version 2
# ==========================================

# 60 new development examples
# 30 scams and 30 legitimate messages

tests = [
    # SCAM MESSAGES
    ("SARS refund pending enter your card number to collect", "scam"),
    ("Your parcel is held until you submit banking details", "scam"),
    ("Receive R5000 if you first send R200", "scam"),
    ("Your wallet is frozen share the security code", "scam"),
    ("Pay school fees into this new personal account", "scam"),
    ("You inherited money pay a release charge", "scam"),
    ("Your streaming account expires sign in on this unknown page", "scam"),
    ("Guaranteed job available after registration payment", "scam"),
    ("Send me your WhatsApp six digit login code", "scam"),
    ("Claim a government grant using your bank card", "scam"),
    ("Pay courier insurance before your buyer can collect", "scam"),
    ("Police demand money to cancel an arrest warrant", "scam"),
    ("Free tablet available after paying with your PIN", "scam"),
    ("Settle your overdue road toll on this strange website", "scam"),
    ("I am your aunt please transfer emergency money", "scam"),
    ("Guaranteed cryptocurrency profits by tomorrow", "scam"),
    ("Your bursary is approved pay processing costs", "scam"),
    ("Your SIM will be blocked send your identity document", "scam"),
    ("Refund available enter your debit card CVV", "scam"),
    ("Type your one time code to unlock a prize", "scam"),
    ("Scan this QR code to connect your bank for a giveaway", "scam"),
    ("Your tax profile will be deleted provide your password", "scam"),
    ("Move your savings into this special secure account", "scam"),
    ("Pay a rental deposit before viewing the property", "scam"),
    ("Open this shortened parcel link and pay delivery charges", "scam"),
    ("Earn guaranteed returns by recruiting three friends", "scam"),
    ("Your cloud photos will disappear unless you log in", "scam"),
    ("Donate by sending your full card details", "scam"),
    ("Send money or your private photos will be exposed", "scam"),
    ("Install remote access software so I can repair your account", "scam"),

    # LEGITIMATE MESSAGES
    ("The bank says never disclose your PIN", "safe"),
    ("Please submit your science assignment on Monday", "safe"),
    ("Swimming training has moved to Wednesday", "safe"),
    ("Your dentist appointment is booked for next month", "safe"),
    ("Mom says dinner is in the fridge", "safe"),
    ("The school newsletter includes our sports calendar", "safe"),
    ("Remember never share your OTP with anybody", "safe"),
    ("The library offers a free coding workshop", "safe"),
    ("The website explains how to change your password", "safe"),
    ("Our class will discuss online fraud tomorrow", "safe"),
    ("The project deadline is tomorrow", "safe"),
    ("Your monthly statement is ready in your banking app", "safe"),
    ("I won first place in the swimming race", "safe"),
    ("Congratulations on passing your examination", "safe"),
    ("Please verify your name on the certificate", "safe"),
    ("Click the submit button on our homework portal", "safe"),
    ("Your parcel arrived and is at reception", "safe"),
    ("Your cousin is coming for dinner on Saturday", "safe"),
    ("Our teacher explained that prizes can be scams", "safe"),
    ("There will be a planned electricity outage", "safe"),
    ("Please reset the classroom laptop after the lesson", "safe"),
    ("The sports shop has a sale on running shoes", "safe"),
    ("Your homework feedback is available at school", "safe"),
    ("The bus departure time changed to seven thirty", "safe"),
    ("Please bring your ID for school registration", "safe"),
    ("The IT lesson covers fake websites", "safe"),
    ("Let me know if you need maths homework help", "safe"),
    ("Dad is collecting us after tennis practice", "safe"),
    ("There is an urgent assembly after break", "safe"),
    ("My phone cannot connect to WiFi during the update", "safe")
]


# ==========================================
# VERSION 1 - ORIGINAL CLASSIFIER
# ==========================================

def predict_v1(message):
    scores = {}

    for label in labels:
        scores[label] = log(
            message_counts[label] / len(training_data)
        )

        total = sum(word_counts[label].values())

        for word in words(message):
            probability = (
                (word_counts[label][word] + 1)
                / (total + len(vocabulary) + 1)
            )

            scores[label] += log(probability)

    return max(scores, key=scores.get)


# ==========================================
# EVALUATION FUNCTION
# ==========================================

def evaluate(model, version):
    correct = 0
    missed_scams = 0
    false_alarms = 0
    detected_scams = 0

    print("\n==============================")
    print("SCAMSHIELD", version)
    print("==============================")

    for message, expected in tests:
        prediction = model(message)

        if prediction == expected:
            correct += 1
        else:
            print("\nFAILED TEST")
            print("Message:", message)
            print("Expected:", expected)
            print("Predicted:", prediction)

        if expected == "scam":
            if prediction == "scam":
                detected_scams += 1
            else:
                missed_scams += 1

        if expected == "safe" and prediction == "scam":
            false_alarms += 1

    total = len(tests)
    accuracy = correct / total * 100

    precision_denominator = detected_scams + false_alarms

    precision = (
        detected_scams / precision_denominator * 100
        if precision_denominator else 0
    )

    recall = detected_scams / 30 * 100

    print("\n------------------------------")
    print("FINAL RESULTS")
    print("------------------------------")
    print(f"Accuracy: {accuracy:.1f}%")
    print(f"Correct: {correct}/{total}")
    print(f"Missed scams: {missed_scams}")
    print(f"False alarms: {false_alarms}")
    print(f"Scam precision: {precision:.1f}%")
    print(f"Scam recall: {recall:.1f}%")

    return accuracy


# ==========================================
# RUN BOTH EXPERIMENTS
# ==========================================

if __name__ == "__main__":

    assert len(tests) == 60
    assert sum(label == "scam" for _, label in tests) == 30

    print("\nSCAMSHIELD AI RESEARCH LAB")
    print("Testing 60 unseen synthetic messages")

    accuracy_v1 = evaluate(
        predict_v1,
        "VERSION 1.0"
    )

    accuracy_v2 = evaluate(
        predict,
        "VERSION 2.0"
    )

    improvement = accuracy_v2 - accuracy_v1

    print("\n==============================")
    print("EXPERIMENT COMPARISON")
    print("==============================")

    print(f"Version 1: {accuracy_v1:.1f}%")
    print(f"Version 2: {accuracy_v2:.1f}%")
    print(f"Difference: {improvement:+.1f} percentage points")

    print("\nResearch experiment completed!")
    print("Results are from synthetic development data.")
    print("They do not prove real-world scam detection accuracy.")