/*
 * Kohler Konnect Bypass Script
 * Allows app to function in rooted Genymotion emulator
 *
 * Required bypasses:
 * - License check (Pairip)
 * - Location injection (fake GPS + region code)
 * - SSL pinning (for mitmproxy)
 * - Root detection (Is.b class + File.* methods)
 * - Emulator detection (Build properties + SystemProperties)
 * - Proxy detection (hide proxy from app while allowing traffic through)
 */

if (Java.available) {
    Java.perform(function() {
        console.log("[*] Kohler Konnect bypass loaded");

        // =============== LICENSE CHECK BYPASS ===============
        try {
            var LicenseClient = Java.use("com.pairip.licensecheck.LicenseClient");
            LicenseClient.initializeLicenseCheck.implementation = function() {
                console.log("[*] LicenseClient.initializeLicenseCheck bypassed");
                var LicenseCheckState = Java.use("com.pairip.licensecheck.LicenseClient$LicenseCheckState");
                LicenseClient.licenseCheckState.value = LicenseCheckState.FULL_CHECK_OK.value;
            };
            LicenseClient.performLocalInstallerCheck.implementation = function() {
                return true;
            };
            console.log("[+] LicenseClient bypass installed");
        } catch(e) {
            console.log("[-] LicenseClient bypass failed: " + e);
        }

        // =============== LOCATION INJECTION ===============
        try {
            var BtDa = Java.use("Bt.d$a");
            var Location = Java.use("android.location.Location");
            var Handler = Java.use("android.os.Handler");
            var Looper = Java.use("android.os.Looper");
            var LocationPermissionActivity = Java.use("com.kohler.hermoth.products.feature.locationpermission.LocationPermissionActivity");

            BtDa.d.implementation = function(activity, callback) {
                console.log("[*] Bt.d.a.d() called - injecting fake location");
                var fakeLoc = Location.$new("gps");
                fakeLoc.setLatitude(43.7508);
                fakeLoc.setLongitude(-87.7819);
                fakeLoc.setAccuracy(10.0);
                fakeLoc.setTime(Java.use("java.lang.System").currentTimeMillis());
                fakeLoc.setElapsedRealtimeNanos(Java.use("android.os.SystemClock").elapsedRealtimeNanos());

                var mainHandler = Handler.$new(Looper.getMainLooper());
                var act = Java.cast(activity, LocationPermissionActivity);

                mainHandler.postDelayed(Java.registerClass({
                    name: "com.frida.FakeLocationInjector",
                    implements: [Java.use("java.lang.Runnable")],
                    methods: {
                        run: function() {
                            try {
                                act.D3(fakeLoc);
                                console.log("[*] Fake location injected successfully");
                            } catch(e) {
                                console.log("[-] Error calling D3: " + e);
                            }
                        }
                    }
                }).$new(), 500);
            };
            console.log("[+] Location injector installed");
        } catch(e) {
            console.log("[-] Location injector failed: " + e);
        }

        try {
            var BtDaA = Java.use("Bt.d$a$a");
            BtDaA.c.implementation = function() {
                console.log("[*] Region code bypassed - returning US");
                return "US";
            };
            console.log("[+] Region code bypass installed");
        } catch(e) {
            console.log("[-] Region code bypass failed: " + e);
        }

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
                console.log("[*] SSLContext.init bypassed");
                this.init(km, TrustManagers, sr);
            };
            console.log("[+] TrustManager bypass installed");
        } catch(e) {
            console.log("[-] TrustManager bypass failed: " + e);
        }

        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                console.log("[*] TrustManagerImpl.verifyChain bypassed for: " + host);
                return untrustedChain;
            };
            console.log("[+] TrustManagerImpl bypass installed");
        } catch(e) {
            console.log("[-] TrustManagerImpl bypass failed: " + e);
        }

        // =============== ROOT DETECTION BYPASS ===============
        try {
            var IsB = Java.use("Is.b");
            IsB.n.implementation = function() {
                console.log("[*] Is.b.n() root detection bypassed");
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
            console.log("[+] Is.b root detection bypass installed");
        } catch(e) {
            console.log("[-] Is.b bypass failed: " + e);
        }

        var rootPaths = [
            "/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/data/local/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
            "/data/data/com.topjohnwu.magisk", "/sbin/.magisk",
            "/system/xbin/busybox", "/system/bin/busybox"
        ];

        function isRootPath(path) {
            for (var i = 0; i < rootPaths.length; i++) {
                if (path === rootPaths[i]) return true;
            }
            var p = path.toLowerCase();
            return p.indexOf("/magisk") !== -1 || p.indexOf("/supersu") !== -1 || p.indexOf("/busybox") !== -1;
        }

        try {
            var File = Java.use("java.io.File");
            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                if (isRootPath(path)) return false;
                return this.exists.call(this);
            };
            File.canRead.implementation = function() {
                var path = this.getAbsolutePath();
                if (isRootPath(path)) return false;
                return this.canRead.call(this);
            };
            File.canExecute.implementation = function() {
                var path = this.getAbsolutePath();
                if (isRootPath(path)) return false;
                return this.canExecute.call(this);
            };
            console.log("[+] File.* root path bypass installed");
        } catch(e) {
            console.log("[-] File.* bypass failed: " + e);
        }

        // =============== EMULATOR DETECTION BYPASS ===============
        try {
            var Build = Java.use("android.os.Build");
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
            console.log("[+] Build properties spoofed");
        } catch(e) {
            console.log("[-] Build spoof failed: " + e);
        }

        try {
            var SystemProperties = Java.use("android.os.SystemProperties");
            var originalGet = SystemProperties.get.overload('java.lang.String');
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                var spoofProps = {
                    "ro.kernel.qemu": "0",
                    "ro.hardware": "exynos2100",
                    "ro.product.model": "SM-G991B",
                    "ro.build.tags": "release-keys",
                    "ro.debuggable": "0",
                    "ro.secure": "1"
                };
                if (spoofProps.hasOwnProperty(key)) return spoofProps[key];
                if (key.indexOf("genymotion") !== -1 || key.indexOf("vbox") !== -1) return "";
                return originalGet.call(this, key);
            };
            SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                var result = SystemProperties.get.overload('java.lang.String').call(this, key);
                return result === "" ? def : result;
            };
            console.log("[+] SystemProperties bypass installed");
        } catch(e) {
            console.log("[-] SystemProperties bypass failed: " + e);
        }

        // =============== PROXY DETECTION BYPASS ===============
        try {
            var System = Java.use("java.lang.System");
            var originalGetProperty = System.getProperty.overload('java.lang.String');
            System.getProperty.overload('java.lang.String').implementation = function(key) {
                var proxyKeys = ["http.proxyHost", "http.proxyPort", "https.proxyHost", "https.proxyPort"];
                if (proxyKeys.indexOf(key) !== -1) return null;
                return originalGetProperty.call(this, key);
            };
            System.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
                var proxyKeys = ["http.proxyHost", "http.proxyPort", "https.proxyHost", "https.proxyPort"];
                if (proxyKeys.indexOf(key) !== -1) return def;
                return this.getProperty(key, def);
            };
            console.log("[+] System.getProperty proxy bypass installed");
        } catch(e) {}

        try {
            var Settings$Global = Java.use("android.provider.Settings$Global");
            var originalGetString = Settings$Global.getString.overload('android.content.ContentResolver', 'java.lang.String');
            Settings$Global.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(resolver, name) {
                if (name === "http_proxy" || name === "global_http_proxy_host" || name === "global_http_proxy_port") return null;
                return originalGetString.call(this, resolver, name);
            };
            console.log("[+] Settings.Global proxy bypass installed");
        } catch(e) {}

        try {
            var ConnectivityManager = Java.use("android.net.ConnectivityManager");
            ConnectivityManager.getDefaultProxy.implementation = function() { return null; };
            console.log("[+] ConnectivityManager.getDefaultProxy bypass installed");
        } catch(e) {}

        try {
            var AndroidProxy = Java.use("android.net.Proxy");
            AndroidProxy.getHost.overload('android.content.Context').implementation = function(ctx) { return null; };
            AndroidProxy.getPort.overload('android.content.Context').implementation = function(ctx) { return -1; };
            console.log("[+] android.net.Proxy bypass installed");
        } catch(e) {}

        try {
            var ProxyInfo = Java.use("android.net.ProxyInfo");
            ProxyInfo.getHost.implementation = function() { return null; };
            ProxyInfo.getPort.implementation = function() { return 0; };
            console.log("[+] ProxyInfo bypass installed");
        } catch(e) {}

        console.log("[*] All bypasses loaded");
    });
}
