/*
 * HTTP Request/Response Capture for Kohler Konnect
 * Hooks OkHttp to capture request bodies before TLS encryption
 */

if (Java.available) {
    Java.perform(function() {
        console.log("[*] HTTP Capture script loaded");

        // Hook Retrofit Call.execute to capture requests
        try {
            var Call = Java.use("retrofit2.Call");
            // This won't work because Call is an interface
        } catch(e) {}

        // Hook OkHttpClient.newCall
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var originalNewCall = OkHttpClient.newCall;
            OkHttpClient.newCall.implementation = function(request) {
                try {
                    var url = request.url().toString();
                    var method = request.method();
                    console.log("\n[HTTP] " + method + " " + url);

                    // Log headers
                    var headers = request.headers();
                    for (var i = 0; i < headers.size(); i++) {
                        var name = headers.name(i);
                        var value = headers.value(i);
                        // Don't log auth tokens fully
                        if (name.toLowerCase().indexOf("auth") !== -1 || name.toLowerCase().indexOf("key") !== -1) {
                            console.log("  " + name + ": " + value.substring(0, 50) + "...");
                        } else {
                            console.log("  " + name + ": " + value);
                        }
                    }

                    // Log body
                    var body = request.body();
                    if (body) {
                        try {
                            var Buffer = Java.use("okio.Buffer");
                            var buffer = Buffer.$new();
                            body.writeTo(buffer);
                            var bodyStr = buffer.readUtf8();
                            console.log("  Body: " + bodyStr);
                        } catch(be) {
                            console.log("  Body: [could not read: " + be + "]");
                        }
                    }
                } catch(e) {
                    console.log("[HTTP] Error logging request: " + e);
                }
                return originalNewCall.call(this, request);
            };
            console.log("[+] OkHttpClient.newCall hook installed");
        } catch(e) {
            console.log("[-] OkHttpClient hook failed: " + e);
        }

        // Try to hook the obfuscated OkHttp
        try {
            // Search for classes that might be OkHttp
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.indexOf("okhttp") !== -1 || className.indexOf("OkHttp") !== -1) {
                        console.log("[*] Found OkHttp class: " + className);
                    }
                },
                onComplete: function() {}
            });
        } catch(e) {}

        // Hook Gson serialization to see what's being converted to JSON
        try {
            var Gson = Java.use("com.google.gson.Gson");
            Gson.toJson.overload('java.lang.Object').implementation = function(obj) {
                var json = this.toJson(obj);
                var className = obj.getClass().getName();
                if (className.indexOf("kohler") !== -1 ||
                    className.indexOf("Anthem") !== -1 ||
                    className.indexOf("Request") !== -1) {
                    console.log("\n[GSON] " + className);
                    console.log("  JSON: " + json);
                }
                return json;
            };
            console.log("[+] Gson.toJson hook installed");
        } catch(e) {
            console.log("[-] Gson hook failed: " + e);
        }

        // Hook Moshi if used
        try {
            var Moshi = Java.use("com.squareup.moshi.Moshi");
            // Moshi hooks here if needed
        } catch(e) {}

        console.log("[*] HTTP capture hooks loaded - control the shower to see requests");
    });
}
