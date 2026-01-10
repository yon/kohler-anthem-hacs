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
| `KOHLER_APIM_KEY` | API subscription key | Captured via mitmproxy + Frida |
| `KOHLER_USERNAME` | Your email | You provide |
| `KOHLER_PASSWORD` | Your password | You provide |
| `KOHLER_DEVICE_ID` | Your shower's ID | Discovered via API |
| `KOHLER_TENANT_ID` | Your customer ID | Discovered via API |

**Important:** The APIM key in the APK is outdated and doesn't work. You **MUST** capture the real key using mitmproxy + Frida (Steps 4-5). The APK extraction only gets client_id and api_resource.

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
- APIM subscription key (global, same for all users)

**Expected output:**
```
==========================================
APK Extraction
==========================================

Decompiling APK with jadx...
Searching for secrets...
Done!

==========================================
Secrets extracted!
==========================================
{
  "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "api_resource": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "apim_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

**Note:** The APK contains an outdated APIM key that doesn't work. You still need to capture the real key using mitmproxy (Steps 4-5).

If client_id or api_resource extraction fails:
1. Try manually searching the `.build/apk/decompiled` folder
2. Look for `msal_config.json` or `auth_config_release.json`

---

## Step 4: Set Up Android for Traffic Capture

> **Required:** The APK contains an outdated APIM key. You must capture the real key via mitmproxy.

You'll capture the APIM key by intercepting traffic from the Kohler app. This requires:
- Mitmproxy running on your Mac
- Android **emulator** (Genymotion) - physical devices won't work due to SSL pinning
- Frida to bypass SSL pinning
- Mitmproxy's CA certificate installed on the emulator

**Why an emulator?** The Kohler app uses SSL certificate pinning, which prevents mitmproxy from intercepting traffic. We use Frida to bypass this, but Frida requires either:
- A rooted Android device, OR
- An Android emulator (easier)

We recommend **Genymotion** (free for personal use): https://www.genymotion.com/download/

### 4a. Install and Set Up Genymotion

1. **Download Genymotion** from https://www.genymotion.com/download/
2. **Install it** (drag to Applications)
3. **Create an account** (free for personal use)
4. **Create a virtual device:**
   - Click "+" to add a new device
   - Choose "Samsung Galaxy S10" or similar (Android 10+)
   - Download and start it

5. **Install Frida server on the emulator:**

   First, install Frida tools if you haven't:
   ```bash
   make install-frida
   ```

   Then download and push frida-server to the emulator:
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
   adb install .build/apk/base.apk
   # Or if you have split APKs:
   adb install-multiple apk/*.apk
   ```

### 4b. Find Your Mac's IP Address

Run:
```bash
ipconfig getifaddr en0
```

Note this IP address (e.g., `192.168.1.100`). You'll need it for the proxy settings.

### 4b. Configure Android Proxy

**On your Android phone/emulator:**

1. Go to: **Settings** → **Network & Internet** → **Wi-Fi**
2. Tap and hold on your connected WiFi network
3. Tap **Modify network** (or the gear icon)
4. Tap **Advanced options**
5. Change "Proxy" from "None" to **Manual**
6. Enter:
   - **Proxy hostname:** `[Your Mac's IP from step 4a]`
   - **Proxy port:** `8080`
7. Tap **Save**

### 4c. Install Mitmproxy Certificate on Android

**While mitmproxy is running (next step will start it):**

1. Open Chrome on Android
2. Go to: `http://mitm.it`
3. Tap **Android** to download the certificate
4. You'll be prompted to name the certificate - enter: `mitmproxy`
5. If prompted for a PIN/password, create one

**If the download doesn't start automatically:**

1. Go to: **Settings** → **Security** → **Encryption & credentials**
2. Tap **Install from storage** or **Install a certificate**
3. Choose **CA certificate**
4. Find and select the downloaded `mitmproxy-ca-cert.pem` file

---

## Step 5: Capture the APIM Key

This captures the real API subscription key by bypassing SSL pinning with Frida and intercepting traffic with mitmproxy.

### 5a. Start Frida Server on Emulator

Open a terminal and run:
```bash
adb shell /data/local/tmp/frida-server &
```

Verify it's running:
```bash
frida-ps -U | head -5
```

You should see a list of processes.

### 5b. Start Mitmproxy

In a **new terminal**, run:
```bash
make proxy
```

This starts mitmproxy on port 8080. Press **ENTER** when prompted.

### 5c. Launch Kohler App with SSL Bypass

In a **third terminal**, launch the app with Frida's SSL bypass:
```bash
frida -U -f com.kohler.hermoth -l scripts/ssl_bypass.js
```

This:
1. Spawns the Kohler Konnect app
2. Injects the SSL bypass script
3. Allows mitmproxy to see the traffic

### 5d. Log In and Capture

**In the emulator:**

1. The Kohler Konnect app should now be open
2. **Log in** with your Kohler account
3. Navigate around:
   - View your devices
   - Tap on your shower

**Watch the mitmproxy terminal.** You should see output like:
```
[Kohler] GET /devices/api/v1/device-management/customer-device/...
         APIM Key: 429e...a493

============================================================
FOUND APIM SUBSCRIPTION KEY!
============================================================

Key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Saved to: .build/captured_apim_key.json
============================================================
```

### 5c. Stop Mitmproxy

Once you see "FOUND APIM SUBSCRIPTION KEY!", press **Ctrl+C** to stop mitmproxy.

### 5d. Remove Proxy from Android

**Important!** Remove the proxy settings or your phone won't have internet:

1. Go to: **Settings** → **Network & Internet** → **Wi-Fi**
2. Tap and hold on your WiFi network
3. Tap **Modify network**
4. Tap **Advanced options**
5. Change "Proxy" back to **None**
6. Tap **Save**

---

## Step 6: Generate Your .env File

Run:
```bash
make env
```

This interactive script will:
1. Load secrets extracted from the APK (Step 3)
2. Load the APIM key captured via mitmproxy (Step 5)
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

  Found APIM_KEY from mitmproxy capture: 429e...

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

## Step 7: Test Your Configuration

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

## Step 8: Install in Home Assistant

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

### Mitmproxy shows no Kohler traffic

- Verify proxy settings on Android (Step 4b)
- Make sure the mitmproxy certificate is installed (Step 4c)
- Try restarting the Kohler app after setting up the proxy

### "APIM key not found"

The Kohler app may be using certificate pinning. You may need to:
1. Use an older version of the app
2. Use Frida to bypass SSL pinning (advanced - see `docs/REVERSE_ENGINEERING.md`)

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
make extract   # Extract secrets from APK
make proxy     # Start mitmproxy to capture APIM key
make env       # Generate .env file
make test      # Test configuration
make clean     # Remove generated files
```
