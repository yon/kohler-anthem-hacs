/*
 * IoT Hub Connection String Capture for Kohler Konnect
 * Hooks Azure IoT Hub SDK to capture connection strings and MQTT messages
 */

if (Java.available) {
    Java.perform(function() {
        console.log("\n[*] IoT Hub Connection String Capture Script Loaded");
        console.log("[*] Waiting for IoT Hub SDK classes to load...");

        // Hook IotHubConnectionString class
        try {
            var IotHubConnectionString = Java.use("com.microsoft.azure.sdk.iot.device.IotHubConnectionString");

            // Constructor hook
            IotHubConnectionString.$init.overload('java.lang.String').implementation = function(connectionString) {
                console.log("\n[IOT HUB] ============================================");
                console.log("[IOT HUB] Connection String Captured!");
                console.log("[IOT HUB] ============================================");
                console.log("[IOT HUB] " + connectionString);
                console.log("[IOT HUB] ============================================");

                // Parse components
                var parts = connectionString.split(";");
                for (var i = 0; i < parts.length; i++) {
                    console.log("[IOT HUB] Part " + i + ": " + parts[i]);
                }
                console.log("[IOT HUB] ============================================\n");

                return this.$init(connectionString);
            };
            console.log("[+] IotHubConnectionString hook installed");
        } catch(e) {
            console.log("[-] IotHubConnectionString hook failed: " + e);
        }

        // Hook DeviceClient creation
        try {
            var DeviceClient = Java.use("com.microsoft.azure.sdk.iot.device.DeviceClient");

            DeviceClient.$init.overload('java.lang.String', 'com.microsoft.azure.sdk.iot.device.IotHubClientProtocol').implementation = function(connString, protocol) {
                console.log("\n[DEVICE CLIENT] ============================================");
                console.log("[DEVICE CLIENT] Creating DeviceClient with connection string:");
                console.log("[DEVICE CLIENT] " + connString);
                console.log("[DEVICE CLIENT] Protocol: " + protocol);
                console.log("[DEVICE CLIENT] ============================================\n");

                return this.$init(connString, protocol);
            };
            console.log("[+] DeviceClient hook installed");
        } catch(e) {
            console.log("[-] DeviceClient hook failed: " + e);
        }

        // Hook InternalClient (parent of DeviceClient)
        try {
            var InternalClient = Java.use("com.microsoft.azure.sdk.iot.device.InternalClient");

            // Hook all constructors
            var constructors = InternalClient.$init.overloads;
            constructors.forEach(function(constructor) {
                try {
                    constructor.implementation = function() {
                        console.log("\n[INTERNAL CLIENT] Creating InternalClient");
                        console.log("[INTERNAL CLIENT] Args: " + JSON.stringify(arguments));
                        for (var i = 0; i < arguments.length; i++) {
                            if (arguments[i] && typeof arguments[i].toString === 'function') {
                                var str = arguments[i].toString();
                                if (str.indexOf("HostName=") !== -1 || str.indexOf("SharedAccessKey=") !== -1) {
                                    console.log("[INTERNAL CLIENT] Connection String found in arg " + i + ":");
                                    console.log("[INTERNAL CLIENT] " + str);
                                }
                            }
                        }
                        return constructor.apply(this, arguments);
                    };
                } catch(e) {}
            });
            console.log("[+] InternalClient hooks installed");
        } catch(e) {
            console.log("[-] InternalClient hook failed: " + e);
        }

        // Hook MQTT connection
        try {
            var Mqtt = Java.use("com.microsoft.azure.sdk.iot.device.transport.mqtt.Mqtt");

            Mqtt.connect.implementation = function() {
                console.log("\n[MQTT] ============================================");
                console.log("[MQTT] Connecting to broker...");
                console.log("[MQTT] ============================================\n");
                return this.connect();
            };
            console.log("[+] Mqtt.connect hook installed");
        } catch(e) {
            console.log("[-] Mqtt hook failed: " + e);
        }

        // Hook MqttIotHubConnection
        try {
            var MqttIotHubConnection = Java.use("com.microsoft.azure.sdk.iot.device.transport.mqtt.MqttIotHubConnection");

            MqttIotHubConnection.open.implementation = function() {
                console.log("\n[MQTT IOT HUB] Opening connection...");
                var result = this.open();
                console.log("[MQTT IOT HUB] Connection opened");
                return result;
            };
            console.log("[+] MqttIotHubConnection hook installed");
        } catch(e) {
            console.log("[-] MqttIotHubConnection hook failed: " + e);
        }

        // Hook Paho MQTT client for actual messages
        try {
            var MqttClient = Java.use("org.eclipse.paho.client.mqttv3.MqttAsyncClient");

            MqttClient.connect.overload('org.eclipse.paho.client.mqttv3.MqttConnectOptions').implementation = function(options) {
                console.log("\n[PAHO MQTT] ============================================");
                console.log("[PAHO MQTT] Connecting with options:");
                console.log("[PAHO MQTT] Server URI: " + this.getServerURI());
                console.log("[PAHO MQTT] Client ID: " + this.getClientId());
                if (options) {
                    try {
                        console.log("[PAHO MQTT] Username: " + options.getUserName());
                        var password = options.getPassword();
                        if (password) {
                            var passStr = Java.use("java.lang.String").$new(password);
                            console.log("[PAHO MQTT] Password (SAS Token): " + passStr.substring(0, Math.min(100, passStr.length())) + "...");
                        }
                    } catch(e) {}
                }
                console.log("[PAHO MQTT] ============================================\n");
                return this.connect(options);
            };
            console.log("[+] Paho MQTT client hook installed");
        } catch(e) {
            console.log("[-] Paho MQTT client hook failed: " + e);
        }

        // Hook message publishing
        try {
            var MqttAsyncClient = Java.use("org.eclipse.paho.client.mqttv3.MqttAsyncClient");

            MqttAsyncClient.publish.overload('java.lang.String', 'org.eclipse.paho.client.mqttv3.MqttMessage').implementation = function(topic, message) {
                console.log("\n[MQTT PUBLISH] ============================================");
                console.log("[MQTT PUBLISH] Topic: " + topic);
                try {
                    var payload = message.getPayload();
                    var payloadStr = Java.use("java.lang.String").$new(payload);
                    console.log("[MQTT PUBLISH] Payload: " + payloadStr);
                } catch(e) {
                    console.log("[MQTT PUBLISH] Payload: [could not decode]");
                }
                console.log("[MQTT PUBLISH] ============================================\n");
                return this.publish(topic, message);
            };
            console.log("[+] MQTT publish hook installed");
        } catch(e) {
            console.log("[-] MQTT publish hook failed: " + e);
        }

        // Hook message subscription callback
        try {
            var MqttCallback = Java.use("org.eclipse.paho.client.mqttv3.MqttCallback");
            // This is an interface, we need to find implementations
        } catch(e) {}

        // Hook IotHubSasToken generation
        try {
            var IotHubSasToken = Java.use("com.microsoft.azure.sdk.iot.device.auth.IotHubSasToken");

            IotHubSasToken.buildSasToken.implementation = function() {
                var token = this.buildSasToken();
                console.log("\n[SAS TOKEN] ============================================");
                console.log("[SAS TOKEN] Generated SAS Token: " + token.substring(0, Math.min(100, token.length())) + "...");
                console.log("[SAS TOKEN] ============================================\n");
                return token;
            };
            console.log("[+] IotHubSasToken hook installed");
        } catch(e) {
            console.log("[-] IotHubSasToken hook failed: " + e);
        }

        // Hook IoTHubSettings class from Kohler app
        try {
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.indexOf("IoTHubSettings") !== -1 ||
                        className.indexOf("iothubsettings") !== -1) {
                        console.log("[*] Found IoT Hub Settings class: " + className);
                        try {
                            var clazz = Java.use(className);
                            var methods = clazz.class.getDeclaredMethods();
                            for (var i = 0; i < methods.length; i++) {
                                console.log("    Method: " + methods[i].getName());
                            }
                        } catch(e) {}
                    }
                },
                onComplete: function() {}
            });
        } catch(e) {}

        console.log("\n[*] IoT Hub capture hooks loaded");
        console.log("[*] Open the app and control the shower to capture connection strings");
        console.log("[*] Look for [IOT HUB], [MQTT], [PAHO MQTT] messages\n");
    });
}
