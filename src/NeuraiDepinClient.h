#ifndef __NEURAI_DEPIN_CLIENT_H__
#define __NEURAI_DEPIN_CLIENT_H__

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <NeuraiDepinMsg.h>
#include <vector>

struct IncomingMessage {
    String sender;
    uint64_t timestamp;
    String content;
    String timeStr;
    String type; // "private" or "group"
    String hash;
    bool decrypted;
};

class NeuraiDepinClient {
public:
    NeuraiDepinClient();

    // 1. Initialization
    void begin(String rpcUrl, String token, String wif);
    
    // 2. Sending
    String sendGroupMessage(String message);
    String sendPrivateMessage(String targetAddress, String message);

    // 3. Receiving
    std::vector<IncomingMessage> receiveMessages(uint64_t &lastTimestamp, int limit = 0, String lastHash = "");

    // Setters / Getters
    void setTimeout(uint32_t ms) { _timeout = ms; }
    void setDebug(bool enabled) { _debug = enabled; }
    String getMyAddress() { return _myAddress; }

private:
    String _rpcUrl;
    String _token;
    String _wif;
    String _myAddress;
    String _myPubKey;
    uint32_t _timeout = 30000;
    bool _debug = false;

    // Internal RPC Helpers
    String rpcCall(String method, JsonArray* params = nullptr);
    std::vector<String> fetchRecipients();
    String getServerPubKey();
    String submitMessage(String payload, bool isWrapped);
    
    String getFormattedTime(uint64_t timestamp);
};

#endif
