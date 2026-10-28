
print("🛡️ WELCOME TO SCAMSHIELD AI")
print("---------------------------")

message = input("Enter a message to scan: ")

warning_signs = [
    "urgent",
    "verify",
    "password",
    "click here",
    "suspended",
    "immediately",
    "otp"
]

detected = []

for word in warning_signs:
    if word in message.lower():
        detected.append(word)

print("\nSCAN RESULTS")
print("---------------------------")

if len(detected) >= 3:
    print("🔴 HIGH RISK - Possible scam!")
elif len(detected) >= 1:
    print("🟡 CAUTION - Suspicious message!")
else:
    print("⚪ No listed warning signs detected.")

print("Warning signs found:", detected)
print("This scan cannot confirm if a message is safe.")
