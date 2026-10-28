# ==========================================
# SCAMSHIELD AI - VERSION 6.0
# DUAL MACHINE LEARNING SYSTEM
# ==========================================

from experiment_v4 import predict_v4
from experiment_v5 import predict_v5


def scan_message(message):

    print("\n================================")
    print("SCAMSHIELD AI - DUAL SCAN")
    print("================================")

    # Run both models independently
    result_v4 = predict_v4(message)
    result_v5 = predict_v5(message)

    print("\nMODEL PREDICTIONS")
    print("-----------------------------")

    print("AI Model 1 (V4):", result_v4.upper())
    print("AI Model 2 (V5):", result_v5.upper())

    # Combine the results
    print("\nFINAL RISK ASSESSMENT")
    print("-----------------------------")

    if result_v4 == "scam" and result_v5 == "scam":

        print("HIGH RISK - POSSIBLE SCAM")
        print("Both models detected scam patterns.")

    elif result_v4 == "scam" or result_v5 == "scam":

        print("CAUTION - NEEDS REVIEW")
        print("The two AI models disagree.")
        print("At least one model detected scam patterns.")

    else:

        print("NO KNOWN SCAM PATTERN DETECTED")
        print("Both models classified the message as safe.")

    print("\nIMPORTANT:")
    print("AI predictions cannot guarantee safety.")
    print("Verify suspicious requests independently.")


# MAIN PROGRAM

if __name__ == "__main__":

    print("\nWELCOME TO SCAMSHIELD DUAL-AI")

    while True:

        message = input(
            "\nEnter message to scan "
            "(or type exit): "
        )

        if message.lower().strip() == "exit":
            print("ScamShield shutting down.")
            break

        if not message.strip():
            print("Please enter a message.")
            continue

        scan_message(message)