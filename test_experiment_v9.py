from experiment_v9 import scan_message

# ScamShield AI - Experiment 9
# Automated functional tests

tests = [
    (
        "Fake millionaire donation",
        "I am a billionaire philanthropist. "
        "You were randomly selected to receive "
        "€800,000 as a gift. Reply with your full address.",
        "HIGH"
    ),
    (
        "Normal school donation",
        "Our school is collecting donations for charity "
        "on Friday. Bring R20 to your class teacher.",
        "NOT_HIGH"
    ),
    (
        "Fake bank alert",
        "Your bank account will be suspended within "
        "30 minutes. Verify your identity at "
        "https://secure-bank-verification.example.com",
        "HIGH"
    ),
    (
        "Normal family message",
        "Hi, remember your school bag tomorrow. "
        "See you in the morning!",
        "NOT_HIGH"
    ),
    (
        "Fake inheritance",
        "You have been selected to receive "
        "$2 million as an inheritance gift. "
        "Provide your bank details to claim it.",
        "HIGH"
    ),
    (
        "School meeting reminder",
        "Reminder: School meeting tomorrow "
        "at 15:00 in the hall.",
        "NOT_HIGH"
    ),
    (
        "Suspicious OTP request",
        "Urgent! Send your OTP immediately "
        "to prevent your account being blocked.",
        "WARNING_OR_HIGH"
    ),
    (
        "Normal OTP safety advice",
        "Never share your OTP or PIN with anyone, "
        "including bank staff.",
        "NOT_HIGH"
    ),
    (
        "Suspicious investment offer",
        "Guaranteed cryptocurrency profits "
        "if you invest R500 today.",
        "WARNING_OR_HIGH"
    ),
    (
        "Swimming reminder",
        "Swimming practice starts tomorrow "
        "at 16:00. Bring your goggles.",
        "NOT_HIGH"
    )
]


def check_result(risk, expected):
    risk = risk.upper()

    if expected == "HIGH":
        return risk.startswith("HIGH")

    if expected == "NOT_HIGH":
        return not risk.startswith("HIGH")

    if expected == "WARNING_OR_HIGH":
        return (
            risk.startswith("HIGH")
            or risk.startswith("NEEDS")
        )

    return False


passed = 0

print("\n" + "=" * 50)
print("SCAMSHIELD AI - EXPERIMENT 9 TEST RESULTS")
print("=" * 50)

for number, (name, message, expected) in enumerate(
    tests, start=1
):
    try:
        result = scan_message(message)
        risk = str(result["risk"])

        success = check_result(risk, expected)

        if success:
            passed += 1
            status = "PASS"
        else:
            status = "FAIL"

        print(f"\nTest {number}: {name}")
        print(f"Expected: {expected}")
        print(f"Actual: {risk}")
        print(f"Result: {status}")

    except Exception as error:
        print(f"\nTest {number}: {name}")
        print(f"ERROR: {type(error).__name__}: {error}")

print("\n" + "=" * 50)
print(f"FINAL SCORE: {passed}/{len(tests)}")
print("=" * 50)

if passed == len(tests):
    print("ALL TESTS PASSED!")
else:
    print("Some tests need improvement.")