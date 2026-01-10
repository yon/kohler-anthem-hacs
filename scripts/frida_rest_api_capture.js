/*
 * REST API Command Body Capture for Kohler Konnect
 * Captures request/response bodies sent to platform API
 */

if (Java.available) {
    Java.perform(function() {
        console.log("[*] REST API Command Capture Script");

        // Minimal bypass
        try {
            var Build = Java.use("android.os.Build");
            Build.HARDWARE.value = "exynos2100";
            Build.MODEL.value = "SM-G991B";
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

        console.log("\n[*] Installing REST API hooks...\n");

        // Find and hook obfuscated OkHttp classes
        var okioBufferClass = null;
        var requestBodyClass = null;

        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                // Look for okio.Buffer (might be obfuscated)
                if (className.indexOf("okio") !== -1 && className.indexOf("Buffer") !== -1) {
                    console.log("[*] Found okio class: " + className);
                    okioBufferClass = className;
                }
                // Look for RequestBody
                if (className.indexOf("okhttp") !== -1 && className.indexOf("RequestBody") !== -1) {
                    console.log("[*] Found okhttp class: " + className);
                }
            },
            onComplete: function() {}
        });

        // Hook Retrofit's Converter to capture serialized request bodies
        try {
            var GsonRequestBodyConverter = Java.use("retrofit2.converter.gson.GsonRequestBodyConverter");
            GsonRequestBodyConverter.convert.implementation = function(value) {
                var result = this.convert(value);
                var className = value.getClass().getName();

                console.log("\n" + "=".repeat(70));
                console.log("[RETROFIT REQUEST BODY]");
                console.log("=".repeat(70));
                console.log("Class: " + className);

                // Get the JSON representation
                try {
                    var Gson = Java.use("com.google.gson.Gson");
                    var gson = Gson.$new();
                    var json = gson.toJson(value);
                    console.log("JSON: " + json);
                } catch(e) {
                    console.log("Value: " + value.toString());
                }
                console.log("=".repeat(70) + "\n");

                return result;
            };
            console.log("[+] GsonRequestBodyConverter hook installed");
        } catch(e) {
            console.log("[-] GsonRequestBodyConverter hook failed: " + e);
        }

        // Hook Retrofit Call.execute and Call.enqueue
        try {
            var OkHttpCall = Java.use("retrofit2.OkHttpCall");

            OkHttpCall.execute.implementation = function() {
                console.log("\n[RETROFIT CALL] execute() called");
                try {
                    var request = this.request.value;
                    if (request) {
                        console.log("  URL: " + request.url().toString());
                        console.log("  Method: " + request.method());
                    }
                } catch(e) {}
                return this.execute();
            };
            console.log("[+] OkHttpCall.execute hook installed");
        } catch(e) {
            console.log("[-] OkHttpCall hook failed: " + e);
        }

        // Hook HttpURLConnection for any direct HTTP calls
        try {
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            var URL = Java.use("java.net.URL");

            HttpURLConnection.getOutputStream.implementation = function() {
                var url = this.getURL().toString();
                if (url.indexOf("kohler") !== -1 || url.indexOf("azure") !== -1) {
                    console.log("\n[HTTP] getOutputStream for: " + url);
                }
                return this.getOutputStream();
            };
        } catch(e) {}

        // Hook OutputStream.write to capture request bodies
        try {
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            ByteArrayOutputStream.write.overload('[B').implementation = function(bytes) {
                try {
                    var str = Java.use("java.lang.String").$new(bytes, "UTF-8");
                    if (str.indexOf("deviceId") !== -1 || str.indexOf("preset") !== -1 ||
                        str.indexOf("valve") !== -1 || str.indexOf("temperature") !== -1 ||
                        str.indexOf("outlet") !== -1 || str.indexOf("warmup") !== -1) {
                        console.log("\n[STREAM WRITE] " + str);
                    }
                } catch(e) {}
                return this.write(bytes);
            };
        } catch(e) {}

        // Hook specific Kohler command request models
        var commandModels = [
            "com.utils.network.retrofit.proxy.platform.model.anthem.AnthemCommandRequestModel",
            "com.utils.network.retrofit.proxy.platform.model.anthem.ControlPresetRequestModel",
            "com.utils.network.retrofit.proxy.platform.model.anthem.WarmupRequestModel",
            "com.utils.network.retrofit.proxy.platform.model.anthem.WritePresetRequestModel",
            "com.kohler.hermoth.products.anthem.data.model.AnthemPresetRequestModel",
            "com.kohler.hermoth.products.anthem.data.model.AnthemControlRequestModel"
        ];

        commandModels.forEach(function(modelName) {
            try {
                var Model = Java.use(modelName);
                var constructors = Model.$init.overloads;
                constructors.forEach(function(ctor) {
                    ctor.implementation = function() {
                        console.log("\n" + "=".repeat(70));
                        console.log("[COMMAND MODEL CREATED] " + modelName);
                        console.log("=".repeat(70));
                        var instance = ctor.apply(this, arguments);

                        // Try to serialize to JSON
                        try {
                            var Gson = Java.use("com.google.gson.Gson");
                            var gson = Gson.$new();
                            var json = gson.toJson(instance);
                            console.log("JSON: " + json);
                        } catch(e) {
                            for (var i = 0; i < arguments.length; i++) {
                                console.log("Arg " + i + ": " + arguments[i]);
                            }
                        }
                        console.log("=".repeat(70) + "\n");
                        return instance;
                    };
                });
                console.log("[+] " + modelName.split(".").pop() + " hook installed");
            } catch(e) {}
        });

        // Search for more command-related classes
        console.log("\n[*] Searching for command request models...");
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if ((className.indexOf("kohler") !== -1 || className.indexOf("hermoth") !== -1) &&
                    (className.indexOf("Request") !== -1 || className.indexOf("Command") !== -1) &&
                    className.indexOf("Model") !== -1) {
                    console.log("[*] Found: " + className);
                }
            },
            onComplete: function() {
                console.log("[*] Search complete\n");
            }
        });

        // Hook Gson toJson for all command-related objects
        try {
            var Gson = Java.use("com.google.gson.Gson");
            Gson.toJson.overload('java.lang.Object').implementation = function(obj) {
                var json = this.toJson(obj);
                var className = obj.getClass().getName();

                // Capture all request/command related
                if (className.indexOf("Request") !== -1 ||
                    className.indexOf("Command") !== -1 ||
                    (className.indexOf("anthem") !== -1 && json.indexOf("deviceId") !== -1) ||
                    (className.indexOf("Anthem") !== -1 && json.indexOf("deviceId") !== -1) ||
                    json.indexOf("presetId") !== -1 ||
                    json.indexOf("experienceId") !== -1 ||
                    json.indexOf("valveId") !== -1 ||
                    json.indexOf("outletId") !== -1 ||
                    json.indexOf("temperatureSetpoint") !== -1) {
                    console.log("\n" + "=".repeat(70));
                    console.log("[COMMAND JSON] " + className);
                    console.log("=".repeat(70));
                    console.log(json);
                    console.log("=".repeat(70) + "\n");
                }
                return json;
            };
            console.log("[+] Gson command JSON capture hook installed");
        } catch(e) {}

        console.log("\n" + "=".repeat(60));
        console.log("[*] READY - Control the shower to capture command format");
        console.log("[*] Try: Start/stop shower, change temp, run preset");
        console.log("=".repeat(60) + "\n");
    });
}
