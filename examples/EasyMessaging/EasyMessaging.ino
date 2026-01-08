#include <WiFi.h>
#include <NeuraiDepinClient.h>

// ==========================================
// ==========================================
// CONFIGURATION (You are in control here)
// ==========================================
const char* ssid = "Name_Wifi";
const char* password = "Pass_Wifi";

//Example RPC url
//const char* rpcUrl = "https://rpc-depin.neurai.org"; 
const char* rpcUrl = "url_rpc"; 
String depinToken = "Name_Token";
String myWIF = "Private_WIF_With_Token"; 
int batchSize = 5; // [NEW] Configurable batch size 

// ==========================================

NeuraiDepinClient depin; 
uint64_t lastTimestamp = 0;
String lastHash = "";

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n\n--- Neurai DePIN Prototype Test ---");

  // 1. WiFi
  WiFi.begin(ssid, password);
  Serial.print("Connecting WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nWiFi Connected!");

  // 2. NTP
  configTime(0, 0, "pool.ntp.org");
  Serial.print("Waiting for NTP");
  while (time(nullptr) < 1000000) { delay(500); Serial.print("."); }
  Serial.println("\nTime Synced!");

  // 3. Initialize Client
  depin.begin(rpcUrl, depinToken, myWIF);
  depin.setDebug(true); // Enable debug output
  Serial.println("Client Ready. Address: " + depin.getMyAddress());

  // 4. Send test message (Group)
  Serial.println("Sending group message...");
  String txid_group = depin.sendGroupMessage("Hello everyone from EasyMessaging!");
  if (txid_group != "") Serial.println("Group Success! TX: " + txid_group);

  // 5. Send test message (Private)
  Serial.println("Sending private message...");
  String txid_priv = depin.sendPrivateMessage("NcHqETeGiPbHXrWcpL2hkPfpbBmNTfHWBW", "Secret hello!");
  if (txid_priv != "") {
    Serial.println("Private Success! TX: " + txid_priv);
  } else {
    Serial.println("Error sending private message (is the address valid/has pubkey?)");
  }
}

void loop() {
  Serial.println("\nPolling for messages...");
  
  // 6. Receive messages and check type (Limit 5 messages per batch)
  std::vector<IncomingMessage> msgs = depin.receiveMessages(lastTimestamp, batchSize, lastHash);
  
  for (auto &m : msgs) {
    if (m.hash.length() > 0) lastHash = m.hash; // Update cursor

    Serial.println("-------------------------");
    Serial.print("[" + m.type + "] "); // "private" or "group"
    Serial.println("From: " + m.sender);
    Serial.println("Time: " + m.timeStr);
    if (m.decrypted) {
      Serial.println("Text: " + m.content);
    } else {
      Serial.println("(Could not decrypt)");
    }
  }

  if (msgs.size() >= batchSize) {
    Serial.println("Batch full, fetching next immediately...");
    delay(500); 
  } else {
    delay(15000); 
  }
}
