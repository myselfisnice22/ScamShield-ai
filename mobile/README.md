# ScamShield AI – phone app (Android & iPhone)

```
Phone app (mobile/)  ──HTTPS──▶  Backend API (backend/api.py)  ──▶  experiment_v10.scan_message
 screens: Scan, Screenshot,        /scan        (text)              (the same Python scanner the
 Results, History, Settings        /scan-image  (OCR + scan)         Streamlit website uses)
```

The phone app never decides anything by itself. It sends the message or screenshot
to the API and shows the answer, so the website and the app always agree.

---

## 1. Run the backend API on your computer

From the **repository root** (the `ScamShield-ai` folder):

```bash
python -m pip install -r backend/requirements.txt
```
```bash
python -m uvicorn backend.api:app --reload --port 8000
```

Open <http://localhost:8000/docs> to try `/scan` in your browser.
Run the API tests with:

```bash
python -m unittest backend.test_api -v
```

## 2. Try the phone screens in your desktop browser

In a second terminal (Windows PowerShell shown):

```bash
$env:SCAMSHIELD_ALLOWED_ORIGINS="http://localhost:5173"; python -m uvicorn backend.api:app --port 8000
```
```bash
cd mobile
```
```bash
npm install
```
```bash
npm run serve
```

Open <http://localhost:5173>. Press F12 → device toolbar to see it at phone size.

## 3. Build and test the Android app (Android Studio)

1. Install **Android Studio**. During setup, let it install the Android SDK.
2. In `mobile/`:
   ```bash
   npm install
   ```
   ```bash
   npm run android
   ```
   This copies the screens into the Android project and opens Android Studio.
3. In Android Studio, pick an emulator or plug in your phone (enable **Developer options →
   USB debugging**), then press ▶ **Run**.
4. Let the app reach the API on your computer:
   ```bash
   adb reverse tcp:8000 tcp:8000
   ```
   The app's default server is `http://localhost:8000`. Check it with **⚙️ Settings → Test connection**.
5. **Test sharing:** open WhatsApp / Messages / Gallery → long-press a message or open a
   screenshot → **Share** → **ScamShield AI**. The app opens and scans it straight away.

After changing anything in `www/`, run `npm run sync` again.

## 4. Put the API online (needed for real users)

Phones out in the world can't reach `localhost`, so the API must be hosted with **HTTPS**.
`backend/Dockerfile` contains everything, including Tesseract OCR. It runs on any host
that supports Docker, for example Render, Railway, Fly.io or Hugging Face Spaces (several
have free tiers). Build context = repository root:

```bash
docker build -f backend/Dockerfile -t scamshield-api .
```

Then put the HTTPS address in `www/config.js` → `defaultApiUrl`, and run `npm run sync`.

## 5. iPhone

Building for iPhone needs **macOS with Xcode**, or a cloud build service such as
Ionic Appflow or Codemagic.

```bash
npx cap add ios
```
```bash
npm run ios
```

* Text scan, screenshot upload, results, history, paste and "Share warning" all work on iPhone.
* **Sharing *into* the app is Android-only for now.** On iPhone it needs a separate
  "Share Extension" target, which has to be built in Xcode.

## 6. Before submitting to the stores – checklist

**Accounts (important):** Google Play and the Apple Developer Program both require the
account holder to be **18 or older**. A parent or guardian must create and own the developer
accounts (Google Play: one-off fee; Apple: yearly fee) and accept the agreements.

- [ ] API hosted on HTTPS and `defaultApiUrl` updated
- [ ] Real-device testing on several phones (small screen, large text, slow internet)
- [ ] Privacy policy published at a public URL (draft: `PRIVACY.md`, to be reviewed by a parent)
- [ ] Google Play **Data safety** form: messages/screenshots are sent to the server for
      checking, not stored, not shared, history stays on the device
- [ ] Apple **App Privacy** answers (same facts)
- [ ] Store screenshots, short description, and the "experimental, not proof of safety" wording
- [ ] Release signing key created in Android Studio (**Build → Generate Signed App Bundle**).
      **Never commit the key or its passwords to GitHub** (`.gitignore` blocks `*.jks`/`*.keystore`).
      Back it up safely. If you lose it, you can't update the app.
- [ ] Upload the `.aab` to Google Play Console → **internal testing** first, then production
- [ ] Version number bumped (`android/app/build.gradle`: `versionCode`, `versionName`)

## Sign-in (optional)

To require sign-in with Clerk, see `CLERK_SETUP.md` in the repository root.

## Files

| Path | What it is |
|---|---|
| `www/index.html`, `styles.css`, `app.js` | The phone screens (plain HTML/CSS/JS, no framework) |
| `www/config.js` | Server address and settings |
| `android/.../ShareReceiverPlugin.java` | Receives text/screenshots shared from other apps |
| `android/.../AndroidManifest.xml` | Share-sheet entries, HTTPS-only network rules, backups off |
| `assets/` | Source images for the app icon and splash screen |
