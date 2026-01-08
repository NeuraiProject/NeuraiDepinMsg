#include "NeuraiDepinClient.h"

NeuraiDepinClient::NeuraiDepinClient() {}

void NeuraiDepinClient::begin(String rpcUrl, String token, String wif) {
    _rpcUrl = rpcUrl;
    if (!_rpcUrl.endsWith("/")) _rpcUrl += "/";
    if (!_rpcUrl.endsWith("rpc")) _rpcUrl += "rpc";

    _token = token;
    _wif = wif;

    // Derive Keys once
    PrivateKey privKey;
    if (privKey.fromWIF(_wif.c_str()) != 0) {
        _myAddress = privKey.address();
        
        PublicKey pub = privKey.publicKey();
        uint8_t pubBytes[33];
        pub.sec(pubBytes, 33);
        
        _myPubKey = "";
        for(int i=0; i<33; i++) {
            if(pubBytes[i] < 0x10) _myPubKey += "0";
            _myPubKey += String(pubBytes[i], HEX);
        }
    }
}

String NeuraiDepinClient::sendGroupMessage(String message) {
    std::vector<String> recipients = fetchRecipients();
    if (recipients.empty()) return "";

    DepinParams params;
    params.token = _token;
    params.senderAddress = _myAddress;
    params.senderPubKey = _myPubKey;
    params.privateKey = _wif;
    params.timestamp = time(nullptr);
    params.message = message;
    params.recipientPubKeys = recipients;
    params.messageType = "group";

    DepinMessageResult res = NeuraiDepinMsg::buildDepinMessage(params);
    
    String payload = res.hex;
    String serverKey = getServerPubKey();
    bool wrapped = false;
    if (serverKey.length() > 0) {
        payload = NeuraiDepinMsg::wrapMessageForServer(payload, serverKey);
        wrapped = true;
    }

    return submitMessage(payload, wrapped);
}

String NeuraiDepinClient::sendPrivateMessage(String targetAddress, String message) {
    if(_debug) Serial.println("DEBUG: sendPrivateMessage to " + targetAddress);
    // 1. Get recipient public key
    DynamicJsonDocument doc(64);
    JsonArray params = doc.to<JsonArray>();
    params.add(targetAddress);
    
    if(_debug) Serial.println("DEBUG: Fetching pubkey...");
    String resJson = rpcCall("getpubkey", &params);
    if(_debug) Serial.println("DEBUG: getpubkey response: " + resJson);
    
    DynamicJsonDocument resDoc(1024);
    deserializeJson(resDoc, resJson);
    
    String targetPubKey = "";
    if (resDoc["result"].is<JsonObject>()) {
        targetPubKey = resDoc["result"]["pubkey"].as<String>();
    } else {
        targetPubKey = resDoc["result"].as<String>(); // Fallback for plain string response
    }

    if(_debug) Serial.println("DEBUG: Target PubKey: " + targetPubKey);
    if (targetPubKey.length() == 0) return "";

    // 2. Build message
    if(_debug) Serial.println("DEBUG: Building Depin Message...");
    DepinParams p;
    p.token = _token;
    p.senderAddress = _myAddress;
    p.senderPubKey = _myPubKey;
    p.privateKey = _wif;
    p.timestamp = time(nullptr);
    p.message = message;
    p.recipientPubKeys = { targetPubKey };
    p.messageType = "private";

    DepinMessageResult res = NeuraiDepinMsg::buildDepinMessage(p);
    
    String payload = res.hex;
    String serverKey = getServerPubKey();
    bool wrapped = false;
    if (serverKey.length() > 0) {
        payload = NeuraiDepinMsg::wrapMessageForServer(payload, serverKey);
        wrapped = true;
    }

    return submitMessage(payload, wrapped);
}

std::vector<IncomingMessage> NeuraiDepinClient::receiveMessages(uint64_t &lastTimestamp, int limit, String lastHash) {
    std::vector<IncomingMessage> results;
    // 1. Prepare Request
    WiFiClientSecure client;
    client.setInsecure();
    
    HTTPClient http;
    if (!http.begin(client, _rpcUrl)) return results;
    
    http.setTimeout(_timeout);
    http.useHTTP10(true); // Disable chunked encoding, simpler for large streams
    http.addHeader("Content-Type", "application/json");

    DynamicJsonDocument reqDoc(1024);
    reqDoc["jsonrpc"] = "2.0";
    reqDoc["id"] = "esp32_receive";
    reqDoc["method"] = "depinreceivemsg";
    JsonArray reqParams = reqDoc.createNestedArray("params");
    reqParams.add(_token);
    reqParams.add(_myAddress);
    reqParams.add(lastTimestamp);
    
    // If we use pagination params, we must send them
    if (limit > 0 || lastHash.length() > 0) {
        reqParams.add(lastHash);
        reqParams.add(limit);
    }

    String reqBody;
    serializeJson(reqDoc, reqBody);

    // 2. Perform Request
    // 2. Perform Request
    int code = http.POST(reqBody);
    
    if(_debug) {
        Serial.println("DEBUG: RPC Call -> depinreceivemsg");
        Serial.println("DEBUG: HTTP Code: " + String(code));
        Serial.println("DEBUG: Free Heap before JSON: " + String(ESP.getFreeHeap()));
        Serial.println("DEBUG: Max Alloc Heap: " + String(ESP.getMaxAllocHeap()));
    }

    if (code != 200) {
        String errRes = http.getString();
        if(_debug) Serial.println("DEBUG: Error Response: " + errRes);
        http.end();
        return results;
    }

    String serverEncHex = "";
    bool isEncrypted = false;
    uint64_t maxTs = lastTimestamp;

    {
        // 3. Manual stream reading to ensure no truncation
        // We read until the server closes the connection (HTTP/1.0 style)
        String resJson = "";
        resJson.reserve(128000); // Pre-allocate to avoid fragmentation
        
        WiFiClient *s = http.getStreamPtr();
        uint32_t start = millis();
        while ((http.connected() || s->available()) && (millis() - start < _timeout)) {
            while (s->available()) {
                char c = s->read();
                resJson += c;
                if (resJson.length() >= 127999) break; // Safety cap
            }
            delay(1); // Give OS some time
        }
        http.end(); 
        
        if(_debug) {
            Serial.println("DEBUG: Raw Response Length: " + String(resJson.length()));
            Serial.println("DEBUG: Free Heap after manual read: " + String(ESP.getFreeHeap()));
        }
        
        if (resJson.length() > 64) {
            if(_debug) Serial.println("DEBUG: End of response: " + resJson.substring(resJson.length() - 64));
        }

        if (resJson.length() > 60000) {
             if(_debug) Serial.println("DEBUG: WARNING! Response length > 60000. ESP32 might have issues handling this size!");
        }

        DynamicJsonDocument resDoc(128000); 
        DeserializationError error = deserializeJson(resDoc, resJson);
        
        if (error) {
            if(_debug) Serial.println("DEBUG: JSON Deserialization Error: " + String(error.c_str()));
            return results;
        }
        if(_debug) Serial.println("DEBUG: Free Heap after resDoc: " + String(ESP.getFreeHeap()));

        if (!resDoc["error"].isNull()) {
            if(_debug) Serial.println("DEBUG: RPC Error: " + resDoc["error"].as<String>());
            return results;
        }

        JsonVariant result = resDoc["result"];
        
        // Handle Privacy Layer Wrapper
        if (result.is<JsonObject>() && result.containsKey("encrypted")) {
            if(_debug) Serial.println("DEBUG: Response is encrypted by Server Privacy Layer");
            const char* serverEncHex = result["encrypted"]; // zero-copy access
            isEncrypted = true;
            
            String decryptedJson = NeuraiDepinMsg::decryptPayload(serverEncHex, _wif);
            
            if (decryptedJson.length() > 0) {
                DynamicJsonDocument innerDoc(128000); 
                deserializeJson(innerDoc, decryptedJson);
                decryptedJson = ""; // Free string memory
                
                // Privacy layer can return Array or Object (with messages)
                JsonVariant decryptedResult = innerDoc.as<JsonVariant>();
                JsonArray messages;

                if (decryptedResult.is<JsonArray>()) {
                    messages = decryptedResult.as<JsonArray>();
                } else if (decryptedResult.is<JsonObject>() && decryptedResult.containsKey("messages")) {
                     messages = decryptedResult["messages"].as<JsonArray>();
                     // We could also capture "has_more" here if we wanted to return it
                }

                if(_debug) Serial.println("DEBUG: Found " + String(messages.size()) + " messages in wrapped response.");
                
                for (JsonObject msg : messages) {
                    uint64_t ts = msg["timestamp"].as<uint64_t>();
                    if (ts > maxTs) maxTs = ts;
                    if (ts <= lastTimestamp && lastTimestamp != 0 && lastHash.length() == 0) continue; 
                    // Note: If using pagination (lastHash set), we don't skip by timestamp strictly

                    IncomingMessage im;
                    if (msg.containsKey("hash")) im.hash = msg["hash"].as<String>();
                    im.sender = msg["sender"].as<String>();
                    im.timestamp = ts;
                    im.type = msg["message_type"].as<String>();
                    im.timeStr = getFormattedTime(ts);
                    
                    const char* pld = msg["encrypted_payload_hex"];
                    im.content = NeuraiDepinMsg::decryptPayload(pld, _wif);
                    im.decrypted = (im.content.length() > 0);
                    results.push_back(im);
                }
            } else {
                if(_debug) Serial.println("DEBUG: Failed to decrypt server wrapped response!");
            }
        } 
        // Handle Standard Response (Array or Object)
        else {
             JsonArray messages;
             if (result.is<JsonArray>()) {
                 if(_debug) Serial.println("DEBUG: Response is plain Array");
                 messages = result.as<JsonArray>();
             } else if (result.is<JsonObject>() && result.containsKey("messages")) {
                 if(_debug) Serial.println("DEBUG: Response is plain Object (Paginated)");
                 messages = result["messages"].as<JsonArray>();
                 // has_more is available: result["has_more"]
             }

             if(_debug) Serial.println("DEBUG: Found " + String(messages.size()) + " messages.");
             
             for (JsonObject msg : messages) {
                uint64_t ts = msg["timestamp"].as<uint64_t>();
                if (ts > maxTs) maxTs = ts;
                // If not using precise pagination (lastHash), filter by older timestamp logic
                if (ts <= lastTimestamp && lastTimestamp != 0 && lastHash.length() == 0) continue;

                IncomingMessage im;
                if (msg.containsKey("hash")) im.hash = msg["hash"].as<String>();
                im.sender = msg["sender"].as<String>();
                im.timestamp = ts;
                im.type = msg["message_type"].as<String>();
                im.timeStr = getFormattedTime(ts);
                
                const char* pld = msg["encrypted_payload_hex"];
                if (pld) {
                    im.content = NeuraiDepinMsg::decryptPayload(pld, _wif);
                }
                im.decrypted = (im.content.length() > 0);
                results.push_back(im);
            }
        }
    } // resDoc and resJson string go out of scope here
    if(_debug) Serial.println("DEBUG: Free Heap after block 1: " + String(ESP.getFreeHeap()));

    // Note: Privacy layer double-decryption block was redundant and removed as it was handled inside the first block
    // The previous code had a duplicate block for `isEncrypted` check outside scope, but logically we can handle it all inside.
    // However, if the first block's scope was to free `resJson`, then we should keep the logic clean.
    // In my rewritten block above, I handled the decryption INSIDE the scope immediately to populate `results`.
    
    lastTimestamp = maxTs;
    return results;
}

// Helpers
String NeuraiDepinClient::rpcCall(String method, JsonArray* params) {
    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;
    if (!http.begin(client, _rpcUrl)) return "";
    
    http.setTimeout(_timeout);
    http.addHeader("Content-Type", "application/json");

    DynamicJsonDocument doc(32768);
    doc["jsonrpc"] = "2.0";
    doc["id"] = "esp32_client";
    doc["method"] = method;
    if (params) {
        JsonArray p = doc.createNestedArray("params");
        for(JsonVariant v : *params) p.add(v);
    }

    String body;
    serializeJson(doc, body);
    
    if(_debug) {
        Serial.println("DEBUG: RPC Call -> " + method);
        // Serial.println("DEBUG: Body -> " + body);
    }
    int code = http.POST(body);
    if(_debug) Serial.println("DEBUG: HTTP Code: " + String(code));
    
    String res = http.getString();
    http.end();

    if (code != 200) {
        if(_debug) Serial.println("DEBUG: Error Response: " + res);
    }
    return (code == 200) ? res : "";
}

std::vector<String> NeuraiDepinClient::fetchRecipients() {
    std::vector<String> keys;
    DynamicJsonDocument doc(64);
    JsonArray params = doc.to<JsonArray>();
    params.add(_token);

    String resJson = rpcCall("listdepinaddresses", &params);
    DynamicJsonDocument resDoc(32768);
    deserializeJson(resDoc, resJson);

    JsonVariant result = resDoc["result"];
    if (result.is<JsonArray>()) {
        JsonArray entries = result.as<JsonArray>();
        for (JsonObject entry : entries) {
            if (entry.containsKey("pubkey")) keys.push_back(entry["pubkey"].as<String>());
        }
    }
    return keys;
}

String NeuraiDepinClient::getServerPubKey() {
    String resJson = rpcCall("depingetmsginfo");
    DynamicJsonDocument resDoc(2048);
    deserializeJson(resDoc, resJson);
    return resDoc["result"]["depinpoolpkey"].as<String>();
}

String NeuraiDepinClient::submitMessage(String payload, bool isWrapped) {
    DynamicJsonDocument doc(65535);
    JsonArray params = doc.to<JsonArray>();
    
    if (isWrapped) {
        JsonObject obj = params.createNestedObject();
        obj["sender"] = _myAddress;
        obj["encrypted"] = payload;
    } else {
        params.add(payload);
    }

    String resJson = rpcCall("depinsubmitmsg", &params);
    DynamicJsonDocument resDoc(2048);
    deserializeJson(resDoc, resJson);
    return resDoc["result"].as<String>();
}

String NeuraiDepinClient::getFormattedTime(uint64_t timestamp) {
    time_t rawTime = (time_t)timestamp;
    struct tm timeinfo;
    gmtime_r(&rawTime, &timeinfo);
    char buffer[30];
    strftime(buffer, 30, "%Y-%m-%d %H:%M:%S", &timeinfo);
    return String(buffer);
}
