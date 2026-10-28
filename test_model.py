
from AI_Model import predict

# SCAMSHIELD AI - ACCURACY TEST

tests = [
    ("Send your bank PIN to claim a reward", "scam"),
    ("Dad please pick me up after school", "safe"),
    ("Your electricity will be disconnected unless you pay", "scam"),
    ("The library closes at four today", "safe"),
    ("Congratulations you have won a prize", "scam"),
    ("Are you coming to football tomorrow", "safe"),
    ("Share your login code to avoid account closure", "scam"),
    ("The maths test starts at eight", "safe"),
    ("Claim your free phone by entering card details", "scam"),
    ("Please bring your swimming equipment", "safe")
]

correct = 0
missed_scams = 0
false_alarms = 0

print("\nSCAMSHIELD AI - ACCURACY TEST\n")

for message, expected in tests:
    prediction = predict(message)

    if prediction == expected:
        correct += 1
        status = "PASS"
    else:
        status = "FAIL"

    if expected == "scam" and prediction == "safe":
        missed_scams += 1

    if expected == "safe" and prediction == "scam":
        false_alarms += 1

    print(f"{status} | Expected: {expected} | AI: {prediction}")
    print(f"Message: {message}\n")

accuracy = (correct / len(tests)) * 100

print("==========================")
print("SCAMSHIELD AI TEST RESULTS")
print("==========================")
print(f"ACCURACY: {accuracy:.1f}%")
print(f"CORRECT: {correct}/{len(tests)}")
print(f"MISSED SCAMS: {missed_scams}")
print(f"FALSE ALARMS: {false_alarms}")
