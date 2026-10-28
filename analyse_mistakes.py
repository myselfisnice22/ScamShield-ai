from experiment_v3 import predict_v3, tests

print("SCAMSHIELD AI - ERROR ANALYSIS")
print("==============================")

missed = []
false_alarms = []

for message, expected in tests:
    prediction = predict_v3(message)

    if expected == "scam" and prediction == "safe":
        missed.append(message)

    if expected == "safe" and prediction == "scam":
        false_alarms.append(message)

print("\nMISSED SCAMS:")
for number, message in enumerate(missed, 1):
    print(f"{number}. {message}")

print("\nFALSE ALARMS:")
for number, message in enumerate(false_alarms, 1):
    print(f"{number}. {message}")

print("\nSUMMARY")
print("Missed scams:", len(missed))
print("False alarms:", len(false_alarms))