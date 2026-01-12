# Kohler Anthem HACS Integration - Complete Setup Guide

This guide walks you through extracting all the secrets needed to configure the Kohler Anthem Home Assistant integration. Follow each step exactly as written.

## What You Need

- A Mac with Homebrew
- Your Kohler Konnect account (email + password)
- **Genymotion Android emulator** (required for SSL bypass)
  - Download free: https://www.genymotion.com/download/
  - Physical devices won't work due to SSL pinning

## What You'll Get

By the end of this guide, you'll have a `.env` file with these secrets:

| Secret | What It Is | Where It Comes From |
|--------|-----------|---------------------|
| `KOHLER_CLIENT_ID` | OAuth client ID | Extracted from APK |
| `KOHLER_API_RESOURCE` | OAuth API scope | Extracted from APK |
| `KOHLER_APIM_KEY` | API subscription key | Captured via Frida (from Firebase Remote Config) |
| `KOHLER_USERNAME` | Your email | You provide |
| `KOHLER_PASSWORD` | Your password | You provide |
| `KOHLER_DEVICE_ID` | Your shower's ID | Discovered via API |
| `KOHLER_TENANT_ID` | Your customer ID | Discovered via API |

**Important:** The APIM key is NOT hardcoded in the APK - it's loaded dynamically from Firebase Remote Config. Our Frida script captures it automatically when you log into the app (Step 4).

---

## Step 0: Clone This Repository

```bash
git clone https://github.com/yon/kohler-anthem-hacs.git
cd kohler-anthem-hacs
```

---

## Step 1: Install Required Tools

Run this command to install all required tools:

```bash
make install
```

This installs:
- Python 3.11 and pip packages (mitmproxy, frida-tools, aiohttp, msal)
- Android Platform Tools (adb)
- jadx (APK decompiler)
- jq (JSON processor)

**Expected output:**
```
Homebrew OK
Python OK
Android Platform Tools OK
Frida OK
APK tools OK

==========================================
All tools installed successfully!
==========================================
```

---

## Step 2: Get the Kohler Konnect APK

You need the Kohler Konnect Android app file (APK). Choose ONE method:

### Method A: From Your Android Phone (Recommended)

1. **Install the app** from Google Play Store:
   - Open Play Store on your phone
   - Search for "Kohler Konnect"
   - Install it

2. **Enable USB debugging** on your phone:
   - Go to: **Settings** → **About phone**
   - Tap "Build number" 7 times (this enables Developer options)
   - Go back to: **Settings** → **Developer options**
   - Enable "USB debugging"

3. **Connect phone to Mac via USB cable**

4. **Accept the debugging prompt** on your phone when it appears

5. **Extract the APK** by running these commands:

   ```bash
   # Create directory for APK
   mkdir -p .build/apk

   # Find where the APK is installed
   adb shell pm path com.kohler.hermoth
   ```

   You'll see output like:
   ```
   package:/data/app/com.kohler.hermoth-XXXX/base.apk
   ```

   Copy that path and run:
   ```bash
   adb pull /data/app/com.kohler.hermoth-XXXX/base.apk .build/apk/base.apk
   ```
   (Replace the path with what you got from the previous command)

### Method B: From APK Mirror Site

1. Go to https://www.apkmirror.com
2. Search for "Kohler Konnect"
3. Download the latest version (choose "APK" not "Bundle")
4. Save the file as `.build/apk/base.apk`

**Verify you have the APK:**
```bash
ls -la .build/apk/base.apk
```

You should see a file around 30-50 MB.

---

## Step 3: Extract Secrets from APK

Run:
```bash
make extract
```

This decompiles the APK and searches for:
- OAuth client ID
- API resource ID

**Expected output:**
```
==========================================
APK Extraction
==========================================

Decompiling APK with jadx...
Searching for secrets...
Note: APIM key must be captured via mitmproxy + Frida (make capture)
Done!

==========================================
Secrets extracted!
==========================================
{
  "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "api_resource": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}

Next step: make bypass (to capture APIM key via Frida)
```

If client_id or api_resource extraction fails:
1. Try manually searching the `.build/decompiled` folder
2. Look for `msal_config.json` or `auth_config_release.json`

---

## Step 4: Capture APIM Key via Frida

The APIM key is NOT hardcoded in the APK - it's loaded dynamically from Firebase Remote Config. Our Frida bypass script captures it automatically when the app stores it in SecurePreferences.

### Why This Is Needed

The Kohler Konnect app has **aggressive protection** that must be bypassed:

1. **SSL Certificate Pinning** - The app refuses to trust certificates except Kohler's
2. **Root Detection** - Uses RootBeer-based detection with 10+ checks
3. **Emulator Detection** - Detects and refuses to run on emulators
4. **Proxy Detection** - Detects HTTP proxies and refuses to make API calls

**Our Frida script (`scripts/frida_bypass.js`) bypasses ALL FOUR layers** and also hooks SecurePreferences to capture the APIM key when the app stores it.

### 4a. Install and Set Up Genymotion

1. **Download Genymotion** from https://www.genymotion.com/download/
2. **Install it** (drag to Applications)
3. **Create an account** (free for personal use)
4. **Create a virtual device:**
   - Click "+" to add a new device
   - Choose "Samsung Galaxy S10" or similar (Android 10+)
   - Download and start it

5. **Install Frida server on the emulator:**

   ```bash
   # Get the emulator's architecture
   adb shell getprop ro.product.cpu.abi
   # Usually "x86_64" for Genymotion

   # Download frida-server (replace version/arch as needed)
   curl -L -o frida-server.xz https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-x86_64.xz
   xz -d frida-server.xz

   # Push to emulator
   adb push frida-server /data/local/tmp/
   adb shell chmod 755 /data/local/tmp/frida-server
   ```

6. **Install the Kohler Konnect APK:**
   ```bash
   adb install dev/apk/base.apk
   ```

### 4b. Start Frida Server

```bash
# Get root and start frida-server
adb root
adb shell /data/local/tmp/frida-server &

# Verify it's running
make frida-status
```

### 4c. Capture the APIM Key

Run:
```bash
make bypass
```

This launches the Kohler app with our bypass script and captures the APIM key.

**In the emulator:**

1. Proceed through the location permission screen
2. **Log in** with your Kohler account
3. Watch the terminal for:

```
============================================================
CAPTURED APIM SUBSCRIPTION KEY (SecurePrefs)!
============================================================
Key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
============================================================

Saving APIM key to: .build/captured_apim_key.json
```

4. Once you see the key, press **Ctrl+C** to exit

---

## Step 5: Generate Your .env File

Run:
```bash
make env
```

This interactive script will:
1. Load secrets extracted from the APK (Step 3)
2. Load the APIM key captured via Frida (Step 4)
3. Ask for your Kohler account credentials
4. Generate a `.env` file

**Follow the prompts:**
```
==========================================
Kohler Anthem .env Generator
==========================================

------------------------------------------------------------
STEP 1: APK Secrets
------------------------------------------------------------

  Found CLIENT_ID from APK extraction: xxxxxxxx...
  Found API_RESOURCE from APK extraction: xxxxxxxx...

------------------------------------------------------------
STEP 2: APIM Subscription Key
------------------------------------------------------------

  Found APIM_KEY from mitmproxy capture: xxxx...

------------------------------------------------------------
STEP 3: Your Kohler Account Credentials
------------------------------------------------------------

  KOHLER_USERNAME (email): your_email@example.com
  KOHLER_PASSWORD: [hidden]

------------------------------------------------------------
STEP 4: Device Info (optional)
------------------------------------------------------------

  KOHLER_DEVICE_ID: [press Enter to skip]
  KOHLER_TENANT_ID: [press Enter to skip]

------------------------------------------------------------
Generating .env file...
------------------------------------------------------------

  Created: .env
  Permissions set to 600 (owner read/write only)

==========================================
SUCCESS!
==========================================
```

---

## Step 6: Test Your Configuration

Run:
```bash
make test
```

This will:
1. Authenticate with your credentials
2. Discover your devices
3. Show your DEVICE_ID and TENANT_ID
4. Test sending a command (warmup)

**Expected output:**
```
==========================================
Testing Configuration
==========================================

============================================================
Step 1: Authenticating...
============================================================
   Trying policy: B2C_1_ROPC_Auth
   Status: 200
Authentication successful!

============================================================
Step 2: Discovering devices...
============================================================
✅ Found 1 device(s):
   1. My Shower (ID: gcs-xxxxxxxxx)

============================================================
TEST RESULTS SUMMARY
============================================================
  ✅ Authentication: Success
  ✅ Device Discovery: Found 1 device(s)
     Device ID: gcs-xxxxxxxxx
     Tenant ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Update .env with Device Info

If the test succeeded, update your `.env` file with the discovered values:

```bash
# Edit .env and fill in KOHLER_DEVICE_ID and KOHLER_TENANT_ID
nano .env
```

---

## Step 7: Install in Home Assistant

1. Copy the `custom_components/kohler_anthem` folder to your Home Assistant's `custom_components` directory

2. Restart Home Assistant

3. Go to: **Settings** → **Devices & Services** → **Add Integration**

4. Search for "Kohler Anthem"

5. Enter your credentials when prompted

---

## Troubleshooting

### "Authentication failed"

- Double-check your email and password
- Make sure you can log into the Kohler Konnect mobile app
- Try resetting your password at kohler.com

### "No devices found"

- Make sure your shower is set up in the Kohler Konnect app
- The device must be provisioned and online

### APIM key not captured

- Make sure you launched the app with `make bypass`, not by tapping the app icon
- Log into the app (the key is captured after authentication)
- Check Frida terminal shows all bypasses installed successfully
- Look for `[+] SecurePreferences APIM key capture installed` in the output

### Kohler app crashes or shows "rooted device" error

The app detected root/emulator. Check the Frida terminal output:

1. **Missing bypass messages** - The script didn't inject properly. Try:
   ```bash
   frida -U -f com.kohler.hermoth -l scripts/frida_bypass.js --no-pause
   ```

2. **"Is.b not found"** - Kohler updated their obfuscation. The root detection class name changed.

3. **App shows "rooted device" error** - A root check wasn't bypassed. Look for `[-]` lines in Frida output showing which hook failed.

4. **All bypasses show installed but still fails** - Make sure you see ALL of:
   - `[+] Is.b root detection bypass installed`
   - `[+] File.* root path bypass installed`
   - `[+] Build properties spoofed`
   - `[+] Proxy detection bypasses installed`

### App shows "Request timeout" after bypasses load

1. **Check location services** - Enable GPS on the emulator:
   ```bash
   adb shell settings put secure location_providers_allowed gps,network
   adb shell settings put secure location_mode 3
   ```

2. **Clear stale proxy settings** - If you previously used mitmproxy:
   ```bash
   adb shell settings delete global http_proxy
   ```

3. **Clear app data and retry** - Cached credentials might be stale:
   ```bash
   adb shell pm clear com.kohler.hermoth
   ```

4. **Restart frida-server** - After emulator reboot/crash:
   ```bash
   adb root
   adb shell pkill frida-server
   adb shell /data/local/tmp/frida-server &
   ```

### Frida shows "unable to find process" or connection errors

```bash
# Restart adb and frida
adb kill-server
adb start-server
adb root
adb shell /data/local/tmp/frida-server &

# Verify connection
frida-ps -U | head -5
```

### "APIM key not found" after running make bypass

The APIM key is stored in SecurePreferences after the app fetches it from Firebase Remote Config (usually during/after login). Make sure:
- You completed the login process
- You saw `[+] SecurePreferences APIM key capture installed` in the output
- The app successfully loaded your devices (got past the login screen)

### APK extraction finds nothing

Try manually searching the decompiled APK:
```bash
grep -r "client_id" .build/apk/decompiled/
grep -r "msal" .build/apk/decompiled/
```

---

## Security Notes

- Your `.env` file contains sensitive credentials
- It's set to mode 600 (only you can read it)
- It's listed in `.gitignore` so it won't be committed
- Never share your `.env` file or its contents

---

## Summary of Commands

```bash
make install   # Install tools
make extract   # Extract client_id/api_resource from APK
make bypass    # Launch app with Frida (captures APIM key)
make env       # Generate .env file
make test      # Test configuration
make clean     # Remove generated files
```
