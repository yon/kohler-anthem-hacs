/*
 * Command Payload Capture for Kohler Konnect
 * Captures the ExecuteControlCommand Direct Method payload
 */

if (Java.available) {
    Java.perform(function() {
        console.log("[*] Command Capture Script - Capturing ExecuteControlCommand payloads");

        // =============== BYPASS (minimal) ===============
        try {
            var Build = Java.use("android.os.Build");
            Build.HARDWARE.value = "exynos2100";
            Build.PRODUCT.value = "o1sxxx";
            Build.MODEL.value = "SM-G991B";
            Build.MANUFACTURER.value = "samsung";
            Build.FINGERPRINT.value = "samsung/o1sxxx/o1s:13/TP1A.220624.014/G991BXXS7DWAA:user/release-keys";
            Build.TAGS.value = "release-keys";
        } catch(e) {}

        try {
            var IsB = Java.use("Is.b");
            IsB.n.implementation = function() { return false; };
        } catch(e) {}

        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function(a,b,c,d,e,f) { return a; };
        } catch(e) {}

        // =============== COMMAND CAPTURE ===============
        console.log("\n[*] Installing command capture hooks...\n");

        // Hook DirectMethodRequest - try all overloads
        try {
            var DirectMethodRequest = Java.use("com.microsoft.azure.sdk.iot.device.edge.DirectMethodRequest");
            var constructors = DirectMethodRequest.$init.overloads;
            constructors.forEach(function(ctor) {
                ctor.implementation = function() {
                    console.log("\n" + "=".repeat(70));
                    console.log("[DIRECT METHOD REQUEST]");
                    console.log("=".repeat(70));
                    for (var i = 0; i < arguments.length; i++) {
                        var arg = arguments[i];
                        if (arg != null) {
                            console.log("Arg " + i + ": " + String(arg));
                        }
                    }
                    console.log("=".repeat(70) + "\n");
                    return ctor.apply(this, arguments);
                };
            });
            console.log("[+] DirectMethodRequest hooks installed");
        } catch(e) {
            console.log("[-] DirectMethodRequest hook failed: " + e);
        }

        // Hook MethodRequest
        try {
            var MethodRequest = Java.use("com.microsoft.azure.sdk.iot.device.twin.MethodRequest");
            var constructors = MethodRequest.$init.overloads;
            constructors.forEach(function(ctor) {
                ctor.implementation = function() {
                    console.log("\n[METHOD REQUEST]");
                    for (var i = 0; i < arguments.length; i++) {
                        console.log("  Arg " + i + ": " + String(arguments[i]));
                    }
                    return ctor.apply(this, arguments);
                };
            });
            console.log("[+] MethodRequest hooks installed");
        } catch(e) {}

        // Hook DeviceClient.invokeMethod
        try {
            var DeviceClient = Java.use("com.microsoft.azure.sdk.iot.device.DeviceClient");
            var methods = DeviceClient.class.getDeclaredMethods();
            for (var i = 0; i < methods.length; i++) {
                var methodName = methods[i].getName();
                if (methodName.indexOf("invoke") !== -1 || methodName.indexOf("Method") !== -1) {
                    console.log("[*] Found method: " + methodName);
                }
            }
        } catch(e) {}

        // Hook all Gson toJson to capture command objects
        try {
            var Gson = Java.use("com.google.gson.Gson");
            Gson.toJson.overload('java.lang.Object').implementation = function(obj) {
                var json = this.toJson(obj);
                var className = obj.getClass().getName();

                // Capture all command-related classes
                if (className.indexOf("Command") !== -1 ||
                    className.indexOf("command") !== -1 ||
                    className.indexOf("Control") !== -1 ||
                    className.indexOf("Preset") !== -1 ||
                    className.indexOf("preset") !== -1 ||
                    className.indexOf("Warmup") !== -1 ||
                    className.indexOf("warmup") !== -1 ||
                    className.indexOf("Request") !== -1 ||
                    className.indexOf("Anthem") !== -1 ||
                    className.indexOf("anthem") !== -1 ||
                    className.indexOf("Valve") !== -1 ||
                    className.indexOf("valve") !== -1 ||
                    className.indexOf("Outlet") !== -1) {
                    console.log("\n[GSON COMMAND] " + className);
                    console.log(json);
                    console.log("");
                }
                return json;
            };
            console.log("[+] Gson command capture hook installed");
        } catch(e) {}

        // Hook IoT Hub Message creation
        try {
            var Message = Java.use("com.microsoft.azure.sdk.iot.device.Message");

            Message.$init.overload('[B').implementation = function(bytes) {
                var str = Java.use("java.lang.String").$new(bytes);
                if (str.indexOf("Command") !== -1 || str.indexOf("command") !== -1 ||
                    str.indexOf("preset") !== -1 || str.indexOf("warmup") !== -1 ||
                    str.indexOf("control") !== -1 || str.indexOf("valve") !== -1 ||
                    str.indexOf("outlet") !== -1 || str.indexOf("temperature") !== -1) {
                    console.log("\n[IOT COMMAND MESSAGE]");
                    console.log(str);
                    console.log("");
                }
                return this.$init(bytes);
            };

            Message.$init.overload('java.lang.String').implementation = function(body) {
                if (body.indexOf("Command") !== -1 || body.indexOf("command") !== -1 ||
                    body.indexOf("preset") !== -1 || body.indexOf("warmup") !== -1 ||
                    body.indexOf("control") !== -1 || body.indexOf("valve") !== -1 ||
                    body.indexOf("outlet") !== -1 || body.indexOf("temperature") !== -1) {
                    console.log("\n[IOT COMMAND MESSAGE]");
                    console.log(body);
                    console.log("");
                }
                return this.$init(body);
            };
            console.log("[+] IoT Message command capture hook installed");
        } catch(e) {}

        // Hook OkHttp for REST API commands
        try {
            var Buffer = Java.use("okio.Buffer");
            var RequestBody = Java.use("okhttp3.RequestBody");

            // Hook the writeTo method to capture request bodies
            RequestBody.writeTo.implementation = function(sink) {
                // Create a buffer to capture the content
                var buffer = Buffer.$new();
                this.writeTo(buffer);
                var content = buffer.readUtf8();

                if (content.length > 0 && content.length < 5000) {
                    if (content.indexOf("preset") !== -1 || content.indexOf("warmup") !== -1 ||
                        content.indexOf("command") !== -1 || content.indexOf("control") !== -1 ||
                        content.indexOf("valve") !== -1 || content.indexOf("outlet") !== -1 ||
                        content.indexOf("temperature") !== -1 || content.indexOf("deviceId") !== -1) {
                        console.log("\n[HTTP REQUEST BODY]");
                        console.log(content);
                        console.log("");
                    }
                }

                // Write to the actual sink
                var buffer2 = Buffer.$new();
                this.writeTo(buffer2);
                sink.writeAll(buffer2);
            };
            console.log("[+] OkHttp RequestBody capture hook installed");
        } catch(e) {
            console.log("[-] OkHttp hook failed: " + e);
        }

        // Search for command-related classes
        console.log("\n[*] Searching for command classes...");
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if ((className.indexOf("kohler") !== -1 || className.indexOf("hermoth") !== -1) &&
                    (className.indexOf("Command") !== -1 || className.indexOf("Control") !== -1 ||
                     className.indexOf("Preset") !== -1 || className.indexOf("Warmup") !== -1)) {
                    console.log("[*] Found: " + className);
                }
            },
            onComplete: function() {
                console.log("[*] Class search complete\n");
            }
        });

        console.log("=".repeat(60));
        console.log("[*] READY - Control the shower to capture command format");
        console.log("[*] Try: Start shower, change temperature, run preset, stop");
        console.log("=".repeat(60) + "\n");
    });
}
