/*
 * REST API Command Body Capture v2 - Hook Retrofit service methods directly
 */

if (Java.available) {
    Java.perform(function() {
        console.log("[*] REST API Command Capture v2");

        // Minimal bypass
        try {
            var Build = Java.use("android.os.Build");
            Build.HARDWARE.value = "exynos2100";
            Build.MODEL.value = "SM-G991B";
            Build.FINGERPRINT.value = "samsung/o1sxxx/o1s:13/TP1A.220624.014/G991BXXS7DWAA:user/release-keys";
            Build.TAGS.value = "release-keys";
        } catch(e) {}
        try { Java.use("Is.b").n.implementation = function() { return false; }; } catch(e) {}
        try { Java.use('com.android.org.conscrypt.TrustManagerImpl').verifyChain.implementation = function(a,b,c,d,e,f) { return a; }; } catch(e) {}

        console.log("\n[*] Searching for Anthem API service classes...\n");

        // Find Retrofit service classes
        var foundServices = [];
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if ((className.indexOf("Service") !== -1 || className.indexOf("Api") !== -1) &&
                    (className.indexOf("anthem") !== -1 || className.indexOf("Anthem") !== -1 ||
                     className.indexOf("platform") !== -1 || className.indexOf("Platform") !== -1 ||
                     className.indexOf("gcs") !== -1 || className.indexOf("Gcs") !== -1)) {
                    foundServices.push(className);
                    console.log("[*] Found: " + className);
                }
            },
            onComplete: function() {
                console.log("\n[*] Found " + foundServices.length + " service classes\n");
            }
        });

        // Hook GsonRequestBodyConverter with correct overload
        try {
            var GsonRequestBodyConverter = Java.use("retrofit2.converter.gson.GsonRequestBodyConverter");
            GsonRequestBodyConverter.convert.overload('java.lang.Object').implementation = function(value) {
                var className = value.getClass().getName();
                console.log("\n" + "=".repeat(70));
                console.log("[REQUEST BODY] " + className);
                console.log("=".repeat(70));

                try {
                    var Gson = Java.use("com.google.gson.Gson");
                    var gson = Gson.$new();
                    var json = gson.toJson(value);
                    console.log(json);
                } catch(e) {
                    console.log("Value: " + value.toString());
                }
                console.log("=".repeat(70) + "\n");

                return this.convert(value);
            };
            console.log("[+] GsonRequestBodyConverter hook installed");
        } catch(e) {
            console.log("[-] GsonRequestBodyConverter: " + e);
        }

        // Hook Retrofit2 RequestBuilder
        try {
            var RequestBuilder = Java.use("retrofit2.RequestBuilder");
            RequestBuilder.build.implementation = function() {
                var request = this.build();
                var url = request.url().toString();
                var method = request.method();

                if (url.indexOf("command") !== -1 || url.indexOf("preset") !== -1 ||
                    url.indexOf("warmup") !== -1 || url.indexOf("control") !== -1 ||
                    url.indexOf("gcs") !== -1) {
                    console.log("\n" + "=".repeat(70));
                    console.log("[RETROFIT REQUEST]");
                    console.log("  Method: " + method);
                    console.log("  URL: " + url);

                    var body = request.body();
                    if (body != null) {
                        try {
                            var Buffer = Java.use("okio.Buffer");
                            var buffer = Buffer.$new();
                            body.writeTo(buffer);
                            var bodyStr = buffer.readUtf8();
                            console.log("  Body: " + bodyStr);
                        } catch(e) {
                            console.log("  Body: [error reading: " + e + "]");
                        }
                    }
                    console.log("=".repeat(70) + "\n");
                }
                return request;
            };
            console.log("[+] RequestBuilder.build hook installed");
        } catch(e) {
            console.log("[-] RequestBuilder: " + e);
        }

        // Hook OkHttp3 Request.Builder
        try {
            var RequestBuilder3 = Java.use("okhttp3.Request$Builder");

            RequestBuilder3.post.overload('okhttp3.RequestBody').implementation = function(body) {
                console.log("\n[OKHTTP POST]");
                if (body != null) {
                    try {
                        var Buffer = Java.use("okio.Buffer");
                        var buffer = Buffer.$new();
                        body.writeTo(buffer);
                        var bodyStr = buffer.readUtf8();
                        if (bodyStr.length > 0 && bodyStr.length < 5000) {
                            console.log("  Body: " + bodyStr);
                        }
                    } catch(e) {}
                }
                return this.post(body);
            };

            RequestBuilder3.put.overload('okhttp3.RequestBody').implementation = function(body) {
                console.log("\n[OKHTTP PUT]");
                if (body != null) {
                    try {
                        var Buffer = Java.use("okio.Buffer");
                        var buffer = Buffer.$new();
                        body.writeTo(buffer);
                        var bodyStr = buffer.readUtf8();
                        if (bodyStr.length > 0 && bodyStr.length < 5000) {
                            console.log("  Body: " + bodyStr);
                        }
                    } catch(e) {}
                }
                return this.put(body);
            };
            console.log("[+] OkHttp Request.Builder hooks installed");
        } catch(e) {
            console.log("[-] OkHttp Request.Builder: " + e);
        }

        // Hook the OkHttp RealCall to capture all requests
        try {
            var RealCall = Java.use("okhttp3.RealCall");
            RealCall.execute.implementation = function() {
                var request = this.request();
                var url = request.url().toString();
                var method = request.method();

                if (url.indexOf("kohler") !== -1 && method !== "GET") {
                    console.log("\n" + "=".repeat(70));
                    console.log("[HTTP " + method + "] " + url);

                    var body = request.body();
                    if (body != null) {
                        try {
                            var Buffer = Java.use("okio.Buffer");
                            var buffer = Buffer.$new();
                            body.writeTo(buffer);
                            var bodyStr = buffer.readUtf8();
                            console.log("Body: " + bodyStr);
                        } catch(e) {
                            console.log("Body: [error]");
                        }
                    }
                    console.log("=".repeat(70) + "\n");
                }
                return this.execute();
            };
            console.log("[+] RealCall.execute hook installed");
        } catch(e) {
            console.log("[-] RealCall: " + e);
        }

        // Also hook RealCall.enqueue for async calls
        try {
            var RealCall = Java.use("okhttp3.RealCall");
            RealCall.enqueue.implementation = function(callback) {
                var request = this.request();
                var url = request.url().toString();
                var method = request.method();

                if (url.indexOf("kohler") !== -1 && method !== "GET") {
                    console.log("\n" + "=".repeat(70));
                    console.log("[HTTP ASYNC " + method + "] " + url);

                    var body = request.body();
                    if (body != null) {
                        try {
                            var Buffer = Java.use("okio.Buffer");
                            var buffer = Buffer.$new();
                            body.writeTo(buffer);
                            var bodyStr = buffer.readUtf8();
                            console.log("Body: " + bodyStr);
                        } catch(e) {}
                    }
                    console.log("=".repeat(70) + "\n");
                }
                return this.enqueue(callback);
            };
            console.log("[+] RealCall.enqueue hook installed");
        } catch(e) {
            console.log("[-] RealCall.enqueue: " + e);
        }

        // Hook all Gson serialization with more verbose output
        try {
            var Gson = Java.use("com.google.gson.Gson");
            Gson.toJson.overload('java.lang.Object').implementation = function(obj) {
                var json = this.toJson(obj);
                var className = obj.getClass().getName();

                // Capture everything that looks like a command/request
                var isCommand = className.indexOf("Request") !== -1 ||
                    className.indexOf("Command") !== -1 ||
                    (json.indexOf("deviceId") !== -1 && json.indexOf("gcs") !== -1) ||
                    json.indexOf("presetId") !== -1 ||
                    json.indexOf("experienceId") !== -1 ||
                    json.indexOf("outletId") !== -1 ||
                    json.indexOf("valveIndex") !== -1 ||
                    json.indexOf("temperatureSetpoint") !== -1 ||
                    json.indexOf("flowSetpoint") !== -1;

                if (isCommand && className.indexOf("microsoft") === -1) {
                    console.log("\n" + "*".repeat(70));
                    console.log("[COMMAND] " + className);
                    console.log("*".repeat(70));
                    console.log(json);
                    console.log("*".repeat(70) + "\n");
                }
                return json;
            };
            console.log("[+] Gson toJson hook installed");
        } catch(e) {}

        console.log("\n" + "=".repeat(60));
        console.log("[*] READY - Control the shower now");
        console.log("=".repeat(60) + "\n");
    });
}
