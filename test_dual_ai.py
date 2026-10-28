from experiment_v4 import predict_v4
from experiment_v5 import predict_v5
from evaluate_scams import tests

# SCAMSHIELD AI - VERSION 6 RESEARCH TEST

def evaluate(name, predictions):
    correct = 0
    missed = 0
    false_alarms = 0

    for (message, actual), prediction in zip(
        tests, predictions
    ):
        if prediction == actual:
            correct += 1

        if actual == "scam" and prediction == "safe":
            missed += 1

        if actual == "safe" and prediction == "scam":
            false_alarms += 1

    total = len(tests)
    accuracy = correct / total * 100
    scam_total = sum(
        label == "scam" for _, label in tests
    )
    recall = (scam_total - missed) / scam_total * 100

    print("\n" + name)
    print("------------------------")
    print(f"Accuracy: {accuracy:.1f}%")
    print(f"Correct: {correct}/{total}")
    print(f"Missed scams: {missed}")
    print(f"False alarms: {false_alarms}")
    print(f"Scam recall: {recall:.1f}%")

# Test both models
v4_results = [
    predict_v4(message)
    for message, actual in tests
]

v5_results = [
    predict_v5(message)
    for message, actual in tests
]

# Dual-AI flags a scam if either model flags it
dual_results = [
    "scam" if "scam" in (v4, v5) else "safe"
    for v4, v5 in zip(v4_results, v5_results)
]

evaluate("VERSION 4", v4_results)
evaluate("VERSION 5", v5_results)
evaluate("VERSION 6 - DUAL AI", dual_results)

# Check disagreements
disagreements = sum(
    a != b for a, b in zip(v4_results, v5_results)
)

print("\nDUAL-AI ANALYSIS")
print("------------------------")
print("Model disagreements:", disagreements)
print("Total messages:", len(tests))
print("\nExperiment complete!")
print("Synthetic development results only.")
print("\nSCAMSHIELD - MODEL DISAGREEMENTS")
print("================================")
for number, ((message, actual), v4, v5) in enumerate(
    zip(tests, v4_results, v5_results), 1
):
    if v4 != v5:
        print(f"\nTest {number}")
        print("Message:", message)
        print("Actual:", actual)
        print("Version 4:", v4)
        print("Version 5:", v5)