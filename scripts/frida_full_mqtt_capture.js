/*
 * Combined: Full SSL/Root/Emulator Bypass + IoT Hub/MQTT Capture for Kohler Konnect
 * This is the complete bypass script plus IoT Hub connection string capture
 */

if (Java.available) {
    Java.perform(function() {
        console.log("[*] Full SSL Pinning + Root Detection + Emulator Detection Bypass + IoT Hub Capture");

    // =============== EMULATOR DETECTION BYPASS ===============
    try {
        var Build = Java.use("android.os.Build");
        var origHardware = Build.HARDWARE.value;
        var emulatorIndicators = ["goldfish", "ranchu", "vbox", "genymotion", "sdk", "google_sdk", "generic"];
        var isEmulator = false;

        for (var i = 0; i < emulatorIndicators.length; i++) {
            if (origHardware.toLowerCase().indexOf(emulatorIndicators[i]) !== -1) {
                isEmulator = true;
                break;
            }
        }

        if (isEmulator) {
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
            var spoofProps = {
                "ro.kernel.qemu": "0",
                "ro.hardware": "exynos2100",
                "ro.product.model": "SM-G991B",
                "ro.product.manufacturer": "samsung",
                "ro.debuggable": "0",
                "ro.secure": "1"
            };
            if (spoofProps.hasOwnProperty(key)) {
                return spoofProps[key];
            }
            if (key.toLowerCase().indexOf("genymotion") !== -1 || key.toLowerCase().indexOf("vbox") !== -1) {
                return "";
            }
            return value;
        };
        console.log("[+] SystemProperties emulator bypass installed");
    } catch(e) {}

    // =============== ROOT DETECTION BYPASS ===============

    // Hook the Kohler obfuscated root detection class Is.b
    try {
        var IsB = Java.use("Is.b");
        IsB.n.implementation = function() {
            console.log("[*] Is.b.n() root detection bypassed!");
            return false;
        };
        IsB.a.implementation = function() { return false; };
        IsB.b.overload('java.lang.String').implementation = function(s) { return false; };
        IsB.c.implementation = function() { return false; };
        IsB.d.implementation = function() { return false; };
        IsB.e.implementation = function() { return false; };
        IsB.f.implementation = function() { return false; };
        IsB.g.implementation = function() { return false; };
        IsB.h.implementation = function() { return false; };
        IsB.j.implementation = function() { return false; };
        IsB.l.implementation = function() { return false; };
        console.log("[+] Kohler Is.b root detection bypass installed");
    } catch(e) {
        console.log("[-] Is.b not found: " + e);
    }

    // Generic File bypass for root paths
    var rootPaths = [
        "/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
        "/system/sd/xbin/su", "/system/bin/failsafe/su",
        "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
        "/data/data/com.topjohnwu.magisk", "/cache/magisk.log",
        "/data/adb/magisk", "/sbin/.magisk",
        "/system/xbin/busybox", "/system/bin/busybox"
    ];

    function isRootPath(path) {
        for (var i = 0; i < rootPaths.length; i++) {
            if (path === rootPaths[i]) return true;
        }
        var pathLower = path.toLowerCase();
        if (pathLower.indexOf("/magisk/") !== -1 || pathLower.indexOf("/.magisk") !== -1 ||
            pathLower.indexOf("/supersu/") !== -1 || pathLower.indexOf("/superuser/") !== -1) {
            return true;
        }
        return false;
    }

    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) { return false; }
            return this.exists.call(this);
        };
        File.canRead.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) { return false; }
            return this.canRead.call(this);
        };
        File.canExecute.implementation = function() {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) { return false; }
            return this.canExecute.call(this);
        };
        console.log("[+] File.* bypass installed");
    } catch(e) {}

    // =============== SSL PINNING BYPASS ===============

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
            this.init(km, TrustManagers, sr);
        };
        console.log("[+] TrustManager bypass installed");
    } catch(e) {}

    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            return untrustedChain;
        };
        console.log("[+] TrustManagerImpl bypass installed");
    } catch(e) {}

    // =============== IOT HUB CONNECTION STRING CAPTURE ===============
    console.log("\n[*] Installing IoT Hub capture hooks...");

    try {
        var IotHubConnectionString = Java.use("com.microsoft.azure.sdk.iot.device.IotHubConnectionString");
        IotHubConnectionString.$init.overload('java.lang.String').implementation = function(connectionString) {
            console.log("\n" + "*".repeat(70));
            console.log("[IOT HUB] CONNECTION STRING CAPTURED!");
            console.log("*".repeat(70));
            console.log(connectionString);
            console.log("*".repeat(70) + "\n");
            return this.$init(connectionString);
        };
        console.log("[+] IotHubConnectionString hook installed");
    } catch(e) {
        console.log("[-] IotHubConnectionString hook failed: " + e);
    }

    try {
        var DeviceClient = Java.use("com.microsoft.azure.sdk.iot.device.DeviceClient");
        var constructors = DeviceClient.$init.overloads;
        constructors.forEach(function(ctor) {
            try {
                ctor.implementation = function() {
                    console.log("\n[DEVICE CLIENT] Creating...");
                    for (var i = 0; i < arguments.length; i++) {
                        var arg = arguments[i];
                        if (arg != null) {
                            var str = String(arg);
                            if (str.indexOf("HostName=") !== -1) {
                                console.log("[DEVICE CLIENT] Connection String: " + str);
                            }
                        }
                    }
                    return ctor.apply(this, arguments);
                };
            } catch(e) {}
        });
        console.log("[+] DeviceClient hooks installed");
    } catch(e) {
        console.log("[-] DeviceClient hook failed: " + e);
    }

    // Hook Gson for MQTT message capture
    try {
        var Gson = Java.use("com.google.gson.Gson");
        Gson.toJson.overload('java.lang.Object').implementation = function(obj) {
            var json = this.toJson(obj);
            var className = obj.getClass().getName();
            if (className.indexOf("kohler") !== -1 || className.indexOf("anthem") !== -1 ||
                className.indexOf("Mqtt") !== -1 || className.indexOf("mqtt") !== -1 ||
                className.indexOf("Valve") !== -1 || className.indexOf("Preset") !== -1) {
                console.log("\n[GSON] " + className);
                console.log("  " + json);
            }
            return json;
        };
        console.log("[+] Gson toJson hook installed");
    } catch(e) {}

    // Hook IoT Hub Message creation
    try {
        var Message = Java.use("com.microsoft.azure.sdk.iot.device.Message");
        Message.$init.overload('[B').implementation = function(bytes) {
            var str = Java.use("java.lang.String").$new(bytes);
            console.log("\n[IOT MESSAGE] " + str);
            return this.$init(bytes);
        };
        Message.$init.overload('java.lang.String').implementation = function(body) {
            console.log("\n[IOT MESSAGE] " + body);
            return this.$init(body);
        };
        console.log("[+] IoT Hub Message hooks installed");
    } catch(e) {}

    // Hook twin operations
    try {
        var Twin = Java.use("com.microsoft.azure.sdk.iot.device.twin.TwinCollection");
        Twin.$init.overload().implementation = function() {
            console.log("\n[DEVICE TWIN] TwinCollection created");
            return this.$init();
        };
    } catch(e) {}

    console.log("\n" + "=".repeat(60));
    console.log("[*] ALL HOOKS INSTALLED - READY FOR CAPTURE");
    console.log("=".repeat(60));
    console.log("[*] Now sign in and control the shower");
    console.log("[*] Watch for [IOT HUB], [IOT MESSAGE], [GSON] messages");
    console.log("=".repeat(60) + "\n");

    });
}
