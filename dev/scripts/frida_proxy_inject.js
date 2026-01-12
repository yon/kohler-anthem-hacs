/**
 * Frida script to INJECT proxy settings into the app.
 * Use this INSTEAD of the proxy bypass hooks when using mitmproxy.
 *
 * This makes the app actively route traffic through mitmproxy.
 * Must be loaded AFTER frida_bypass.js to override the proxy bypass hooks.
 *
 * Usage:
 *   frida -D 127.0.0.1:6555 -f com.kohler.hermoth \
 *     -l scripts/frida_bypass.js \
 *     -l dev/scripts/frida_proxy_inject.js
 */

// Get host IP from environment or use default
// For Genymotion, 10.0.3.2 is the host machine
var PROXY_HOST = "10.0.3.2";
var PROXY_PORT = 8080;

Java.perform(function() {
    console.log("[*] Loading proxy injection hooks (host=" + PROXY_HOST + ", port=" + PROXY_PORT + ")");

    // Override System.getProperty to return proxy settings
    try {
        var System = Java.use("java.lang.System");

        System.getProperty.overload('java.lang.String').implementation = function(key) {
            if (key === "http.proxyHost" || key === "https.proxyHost") {
                console.log("[*] System.getProperty(" + key + ") -> " + PROXY_HOST);
                return PROXY_HOST;
            }
            if (key === "http.proxyPort" || key === "https.proxyPort") {
                console.log("[*] System.getProperty(" + key + ") -> " + PROXY_PORT);
                return String(PROXY_PORT);
            }
            return this.getProperty(key);
        };

        System.getProperty.overload('java.lang.String', 'java.lang.String').implementation = function(key, def) {
            if (key === "http.proxyHost" || key === "https.proxyHost") {
                return PROXY_HOST;
            }
            if (key === "http.proxyPort" || key === "https.proxyPort") {
                return String(PROXY_PORT);
            }
            return this.getProperty(key, def);
        };
        console.log("[+] System.getProperty proxy injection installed");
    } catch(e) {
        console.log("[-] System.getProperty proxy injection failed: " + e);
    }

    // Override Settings.Global to return proxy settings
    try {
        var Settings = Java.use("android.provider.Settings$Global");
        Settings.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(resolver, name) {
            if (name === "http_proxy") {
                var proxy = PROXY_HOST + ":" + PROXY_PORT;
                console.log("[*] Settings.Global.getString(http_proxy) -> " + proxy);
                return proxy;
            }
            if (name === "global_http_proxy_host") {
                return PROXY_HOST;
            }
            if (name === "global_http_proxy_port") {
                return String(PROXY_PORT);
            }
            return this.getString(resolver, name);
        };
        console.log("[+] Settings.Global proxy injection installed");
    } catch(e) {
        console.log("[-] Settings.Global proxy injection failed: " + e);
    }

    // Override ConnectivityManager.getDefaultProxy
    try {
        var ConnectivityManager = Java.use("android.net.ConnectivityManager");
        var ProxyInfo = Java.use("android.net.ProxyInfo");

        ConnectivityManager.getDefaultProxy.implementation = function() {
            var proxy = ProxyInfo.buildDirectProxy(PROXY_HOST, PROXY_PORT);
            console.log("[*] ConnectivityManager.getDefaultProxy() -> " + PROXY_HOST + ":" + PROXY_PORT);
            return proxy;
        };
        console.log("[+] ConnectivityManager.getDefaultProxy proxy injection installed");
    } catch(e) {
        console.log("[-] ConnectivityManager.getDefaultProxy proxy injection failed: " + e);
    }

    // Override android.net.Proxy methods
    try {
        var AndroidProxy = Java.use("android.net.Proxy");
        AndroidProxy.getHost.overload('android.content.Context').implementation = function(ctx) {
            console.log("[*] android.net.Proxy.getHost() -> " + PROXY_HOST);
            return PROXY_HOST;
        };
        AndroidProxy.getPort.overload('android.content.Context').implementation = function(ctx) {
            console.log("[*] android.net.Proxy.getPort() -> " + PROXY_PORT);
            return PROXY_PORT;
        };
        console.log("[+] android.net.Proxy proxy injection installed");
    } catch(e) {
        console.log("[-] android.net.Proxy proxy injection failed: " + e);
    }

    // Override ProxyInfo methods
    try {
        var ProxyInfo = Java.use("android.net.ProxyInfo");
        ProxyInfo.getHost.implementation = function() {
            return PROXY_HOST;
        };
        ProxyInfo.getPort.implementation = function() {
            return PROXY_PORT;
        };
        console.log("[+] ProxyInfo proxy injection installed");
    } catch(e) {
        console.log("[-] ProxyInfo proxy injection failed: " + e);
    }

    // Hook OkHttp to use proxy
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
        var ProxyCls = Java.use("java.net.Proxy");
        var ProxyType = Java.use("java.net.Proxy$Type");
        var InetSocketAddress = Java.use("java.net.InetSocketAddress");

        OkHttpClientBuilder.build.implementation = function() {
            console.log("[*] OkHttpClient.Builder.build() - injecting proxy");
            var addr = InetSocketAddress.$new(PROXY_HOST, PROXY_PORT);
            var proxy = ProxyCls.$new(ProxyType.HTTP.value, addr);
            this.proxy(proxy);
            return this.build();
        };
        console.log("[+] OkHttpClient proxy injection installed");
    } catch(e) {
        console.log("[-] OkHttpClient proxy injection failed: " + e);
    }

    // Hook Retrofit if used
    try {
        var Retrofit = Java.use("retrofit2.Retrofit");
        var RetrofitBuilder = Java.use("retrofit2.Retrofit$Builder");

        RetrofitBuilder.build.implementation = function() {
            console.log("[*] Retrofit.Builder.build() called");
            return this.build();
        };
        console.log("[+] Retrofit logging installed");
    } catch(e) {
        // Retrofit might not be loaded yet
    }

    console.log("[*] Proxy injection hooks loaded");
});
