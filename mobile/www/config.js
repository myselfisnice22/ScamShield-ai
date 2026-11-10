// ScamShield AI - app configuration.
//
// defaultApiUrl is where the phone app sends messages for checking.
//
// * Testing on your computer's browser:   "http://localhost:8000"
// * Testing on an Android phone/emulator: "http://localhost:8000" and run
//       adb reverse tcp:8000 tcp:8000
//   so the phone's "localhost" reaches the API running on your computer.
// * Store release: the HTTPS address of your hosted backend, e.g.
//       "https://scamshield-api.onrender.com"
//
// Users can also change the address in the app's Settings screen.
window.SCAMSHIELD_CONFIG = {
  defaultApiUrl: "http://localhost:8000",
  requestTimeoutMs: 45000,
  maxHistory: 20,

  // Clerk sign-in. Leave "" to run without sign-in.
  // Paste your Clerk PUBLISHABLE key (starts with pk_test_ or pk_live_).
  // The publishable key is safe to put in the app. NEVER put the Clerk
  // SECRET key (sk_...) in the app or on GitHub.
  clerkPublishableKey: "",
};
