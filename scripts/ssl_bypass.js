/*
 * SSL Pinning + Root Detection + Emulator Detection Bypass for Android
 * Comprehensive bypass for Kohler Konnect
 */

if (Java.available) {
    Java.perform(function() {
        console.log("[*] SSL Pinning + Root Detection + Emulator Detection Bypass loaded");

    // =============== EMULATOR DETECTION BYPASS ===============

    // Bypass Build properties that reveal emulator
    try {
        var Build = Java.use("android.os.Build");

        // Save original values for logging
        var origHardware = Build.HARDWARE.value;
        var origProduct = Build.PRODUCT.value;
        var origModel = Build.MODEL.value;
        var origManufacturer = Build.MANUFACTURER.value;
        var origBrand = Build.BRAND.value;
        var origDevice = Build.DEVICE.value;
        var origBoard = Build.BOARD.value;
        var origFingerprint = Build.FINGERPRINT.value;

        console.log("[*] Original Build values:");
        console.log("    HARDWARE: " + origHardware);
        console.log("    PRODUCT: " + origProduct);
        console.log("    MODEL: " + origModel);
        console.log("    MANUFACTURER: " + origManufacturer);
        console.log("    BRAND: " + origBrand);
        console.log("    DEVICE: " + origDevice);

        // Check if running in emulator and spoof values
        var emulatorIndicators = ["goldfish", "ranchu", "vbox", "genymotion", "sdk", "google_sdk", "generic"];
        var isEmulator = false;
        for (var i = 0; i < emulatorIndicators.length; i++) {
            if (origHardware.toLowerCase().indexOf(emulatorIndicators[i]) !== -1 ||
                origProduct.toLowerCase().indexOf(emulatorIndicators[i]) !== -1 ||
                origModel.toLowerCase().indexOf(emulatorIndicators[i]) !== -1) {
                isEmulator = true;
                break;
            }
        }

        if (isEmulator) {
            // Spoof as Samsung Galaxy S21
            Build.HARDWARE.value = "exynos2100";
            Build.PRODUCT.value = "o1sxxx";
            Build.MODEL.value = "SM-G991B";
            Build.MANUFACTURER.value = "samsung";
            Build.BRAND.value = "samsung";
            Build.DEVICE.value = "o1s";
            Build.BOARD.value = "exynos2100";
            Build.FINGERPRINT.value = "samsung/o1sxxx/o1s:13/TP1A.220624.014/G991BXXS7DWAA:user/release-keys";
            Build.TAGS.value = "release-keys";
            Build.TYPE.value = "user";
            Build.USER.value = "android-build";
            Build.HOST.value = "build.samsung.com";
            console.log("[+] Build properties spoofed to Samsung Galaxy S21");
        }
    } catch(e) {
        console.log("[-] Build spoof failed: " + e);
    }

    // Bypass SystemProperties for emulator detection
    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        var originalGet = SystemProperties.get.overload('java.lang.String');
        SystemProperties.get.overload('java.lang.String').implementation = function(key) {
            var value = originalGet.call(this, key);

            // Properties that reveal emulator
            var spoofProps = {
                "ro.kernel.qemu": "0",
                "ro.hardware": "exynos2100",
                "ro.product.model": "SM-G991B",
                "ro.product.manufacturer": "samsung",
                "ro.product.brand": "samsung",
                "ro.product.device": "o1s",
                "ro.product.board": "exynos2100",
                "ro.product.name": "o1sxxx",
                "ro.build.product": "o1s",
                "ro.build.fingerprint": "samsung/o1sxxx/o1s:13/TP1A.220624.014/G991BXXS7DWAA:user/release-keys",
                "ro.build.tags": "release-keys",
                "ro.build.type": "user",
                "ro.debuggable": "0",
                "ro.secure": "1",
                "init.svc.qemu-props": "",
                "qemu.sf.lcd_density": "",
                "ro.kernel.android.qemud": "",
                "ro.kernel.qemu.gles": "",
                "ro.boot.hardware": "exynos2100",
                "ro.hardware.audio.primary": "samsung",
                "gsm.version.baseband": "G991BXXS7DWAA",
                "gsm.nitz.time": ""  // Return empty to avoid emulator detection
            };

            if (spoofProps.hasOwnProperty(key)) {
                console.log("[*] SystemProperties.get spoofed: " + key + " = " + spoofProps[key]);
                return spoofProps[key];
            }

            // Block properties that reveal Genymotion
            if (key.toLowerCase().indexOf("genymotion") !== -1 ||
                key.toLowerCase().indexOf("vbox") !== -1) {
                console.log("[*] SystemProperties.get blocked: " + key);
                return "";
            }

            return value;
        };

        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            var result = SystemProperties.get.overload('java.lang.String').call(this, key);
            return result === "" ? def : result;
        };

        console.log("[+] SystemProperties emulator bypass installed");
    } catch(e) {
        console.log("[-] SystemProperties emulator bypass failed: " + e);
    }

    // Bypass TelephonyManager for emulator detection
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");

        TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
            console.log("[*] TelephonyManager.getNetworkOperatorName spoofed");
            return "T-Mobile";
        };

        TelephonyManager.getSimOperatorName.overload().implementation = function() {
            console.log("[*] TelephonyManager.getSimOperatorName spoofed");
            return "T-Mobile";
        };

        TelephonyManager.getNetworkOperator.overload().implementation = function() {
            console.log("[*] TelephonyManager.getNetworkOperator spoofed");
            return "310260";  // T-Mobile MCC/MNC
        };

        TelephonyManager.getSimOperator.overload().implementation = function() {
            console.log("[*] TelephonyManager.getSimOperator spoofed");
            return "310260";
        };

        TelephonyManager.getPhoneType.overload().implementation = function() {
            console.log("[*] TelephonyManager.getPhoneType spoofed");
            return 1;  // PHONE_TYPE_GSM
        };

        console.log("[+] TelephonyManager emulator bypass installed");
    } catch(e) {
        console.log("[-] TelephonyManager emulator bypass failed: " + e);
    }

    // =============== ROOT DETECTION BYPASS ===============

    // Hook the Kohler obfuscated root detection class Is.b
    try {
        var IsB = Java.use("Is.b");
        // n() is the main root detection method - bypass it completely
        IsB.n.implementation = function() {
            console.log("[*] Is.b.n() root detection bypassed!");
            return false;
        };
        // Also bypass all individual check methods
        IsB.a.implementation = function() { return false; };  // RootBeerNative check
        IsB.b.overload('java.lang.String').implementation = function(s) {
            console.log("[*] Is.b.b() binary check bypassed: " + s);
            return false;
        };
        IsB.c.implementation = function() { return false; };  // getprop check
        IsB.d.implementation = function() { return false; };  // magisk check
        IsB.e.implementation = function() { return false; };  // mount rw check
        IsB.f.implementation = function() { return false; };  // native root check
        IsB.g.implementation = function() { return false; };  // which su check
        IsB.h.implementation = function() { return false; };  // dangerous apps check
        IsB.j.implementation = function() { return false; };  // root packages check
        IsB.l.implementation = function() { return false; };  // test-keys check
        console.log("[+] Kohler Is.b root detection bypass installed");
    } catch(e) {
        console.log("[-] Is.b not found: " + e);
    }

    // Generic File bypass for root paths - ALL file check methods
    var rootPaths = [
        "/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
        "/system/app/SuperSU/SuperSU.apk",
        "/data/data/com.noshufou.android.su",
        "/data/data/eu.chainfire.supersu",
        "/data/data/com.koushikdutta.superuser",
        "/data/data/com.thirdparty.superuser",
        "/data/data/com.topjohnwu.magisk",
        "/cache/magisk.log", "/data/adb/magisk", "/sbin/.magisk",
        "/system/xbin/daemonsu", "/dev/com.koushikdutta.superuser.daemon",
        "/system/bin/.ext/su", "/system/usr/we-need-root/su",
        "/cache/su", "/data/su", "/dev/su",
        "/system/xbin/busybox", "/system/bin/busybox",
        "/product/bin/su", "/odm/bin/su", "/vendor/bin/su", "/vendor/xbin/su",
        "/apex/com.android.runtime/bin/su", "/apex/com.android.art/bin/su",
        "/system_ext/bin/su"
    ];

    function isRootPath(path) {
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) return true;
        }
        var pathLower = path.toLowerCase();
        var rootPatterns = ["/magisk/", "/.magisk", "/supersu/", "/superuser/", "/xposed/", "/busybox"];
        for (var i = 0; i < rootPatterns.length; i++) {
            if (pathLower.indexOf(rootPatterns[i]) !== -1) return true;
        }
        return false;
    }

    try {
        var File = Java.use("java.io.File");

        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) {
                console.log("[*] File.exists blocked: " + path);
                return false;
            }
            return this.exists.call(this);
        };

        File.canRead.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) {
                console.log("[*] File.canRead blocked: " + path);
                return false;
            }
            return this.canRead.call(this);
        };

        File.canWrite.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) {
                console.log("[*] File.canWrite blocked: " + path);
                return false;
            }
            return this.canWrite.call(this);
        };

        File.canExecute.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) {
                console.log("[*] File.canExecute blocked: " + path);
                return false;
            }
            return this.canExecute.call(this);
        };

        File.isFile.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) {
                console.log("[*] File.isFile blocked: " + path);
                return false;
            }
            return this.isFile.call(this);
        };

        File.isDirectory.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) {
                console.log("[*] File.isDirectory blocked: " + path);
                return false;
            }
            return this.isDirectory.call(this);
        };

        console.log("[+] File.* bypass installed (exists, canRead, canWrite, canExecute, isFile, isDirectory)");
    } catch(e) {
        console.log("[-] File bypass failed: " + e);
    }

    // =============== SSL PINNING BYPASS ===============

    // TrustManager bypass
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'com.frida.BypassTrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });

        var TrustManagers = [TrustManager.$new()];

        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
            console.log("[*] SSLContext.init bypassed");
            this.init(km, TrustManagers, sr);
        };
        console.log("[+] TrustManager bypass installed");
    } catch(e) {
        console.log("[-] TrustManager bypass failed: " + e);
    }

    // TrustManagerImpl bypass (Android 7+)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[*] TrustManagerImpl.verifyChain bypassed for: " + host);
            return untrustedChain;
        };
        console.log("[+] TrustManagerImpl bypass installed");
    } catch(e) {}

    console.log("[*] All bypasses loaded - try signing in now");
    console.log("[*] Tip: Look for 'bypassed' messages above to see which checks the app is performing");

    });
} // end if Java.available
