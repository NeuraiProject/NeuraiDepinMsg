/*
 * EasyMessaging — minimal DePIN Messaging Protocol 2 client on an ESP32.
 *
 * Unattended-device setup (plan v3 §4): the firmware ships a FULL PIN — the
 * service URL, the pool root token and the pool public key — so nothing is
 * trusted on first contact and no button has to be pressed. Ask the project
 * running the pool for its `depinpoolpkey` and root token, and paste them
 * below. Every reply is verified against that key before it is decoded.
 *
 * Requirements:
 *   - Wi-Fi and a synced clock (NTP below): challenge requests carry the
 *     real Unix time in milliseconds and are refused with a wrong clock.
 *   - A holder key: WIF of a P2PKH address that holds the token AND has
 *     revealed its public key on chain (it must have spent at least once).
 *   - The CA certificate of the RPC endpoint (TLS). setInsecure(true) exists
 *     for lab use only.
 *
 * Never embed a real WIF in a public sketch; load it from NVS/Preferences.
 */
#include <WiFi.h>
#include <time.h>
#include <NeuraiDepinClient.h>

// ==========================================
// CONFIGURATION
// ==========================================
const char * ssid     = "Name_Wifi";
const char * password = "Pass_Wifi";

const char * rpcUrl      = "https://rpc-testnet-depin.neurai.org";   // base URL: "/rpc" is added once
const char * poolRoot    = "&TEST";                                   // pool root token (from depingetmsginfo)
const char * poolPubKey  = "03649c7a094c76b63995e60f891c13d9440b12b65b46ad8426cb153789e816b01b"; // depinpoolpkey (66 hex)
const char * channel     = "&TEST/SEC";                               // token this device talks on
const char * myWIF       = "cW8vy4nJ...";                             // holder key (compressed WIF) — load from NVS in production
const char * destAddress = "tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n";     // private message target

// Root CA of the RPC endpoint (PEM). Leave NULL only with setInsecure(true).
const char * rootCA = NULL;

const size_t pageSize = 2;   // small pages: a page of N messages can weigh N × (5–25) KB
// ==========================================

NeuraiDepinClient client;
String cursor = "";          // persist this (Preferences) to resume after a reboot

static void waitForClock() {
  configTime(0, 0, "pool.ntp.org", "time.google.com");
  Serial.print("Waiting for NTP");
  while (time(nullptr) < 1700000000) { delay(500); Serial.print("."); }
  Serial.println(" synced");
}

static void pollOnce() {
  int pages = 0;
  do {
    DepinPageResult page = client.receivePage(cursor, pageSize);
    if (!page.ok) {
      Serial.printf("receive failed: %s %s\n", client.lastErrorName(), client.lastErrorDetail().c_str());
      if (client.lastError() == depin::Err::RateLimited) delay(client.retryAfterSec() * 1000);
      return;
    }
    for (auto & m : page.messages) {
      Serial.printf("[%s] %s %s (%s): %s\n", m.type.c_str(), m.timeStr.c_str(), m.sender.c_str(),
                    m.token.c_str(), m.content.c_str());
    }
    if (page.rejected) Serial.printf("  (%u rows rejected: bad signature / scope / not for us)\n", (unsigned)page.rejected);
    cursor = page.nextCursor;          // confirm the cursor only after processing the page
    if (!page.shouldContinue) break;
  } while (++pages < 10);              // bound pages per poll: quota and proxy limits
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n--- Neurai DePIN messaging (protocol 2) ---");

  WiFi.begin(ssid, password);
  Serial.print("Connecting WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println(" connected");
  waitForClock();

  if (rootCA) client.setCACert(rootCA); else client.setInsecure(true);   // lab only
  client.setPoolPin(poolPubKey, poolRoot);   // full pin: RequirePin, no TOFU
  client.setPageLimit(pageSize);
  client.setDebug(true);

  if (!client.begin(rpcUrl, channel, myWIF)) {
    Serial.printf("begin failed: %s %s\n", client.lastErrorName(), client.lastErrorDetail().c_str());
    return;
  }
  Serial.println("Address: " + client.getMyAddress());

  if (!client.bootstrap()) {
    Serial.printf("bootstrap failed: %s %s\n", client.lastErrorName(), client.lastErrorDetail().c_str());
    return;                              // a pin mismatch is an alert, never something to accept silently
  }
  Serial.printf("Pool %s ready: max %u recipients, %u bytes per message\n",
                client.poolRoot().c_str(), (unsigned)client.maxRecipients(), (unsigned)client.maxMessageSize());

  String h = client.sendGroupMessage("Hello everyone from EasyMessaging!");
  if (h.length()) Serial.println("Group message confirmed: " + h);
  else Serial.printf("group send failed: %s %s\n", client.lastErrorName(), client.lastErrorDetail().c_str());

  h = client.sendPrivateMessage(destAddress, "Secret hello!");
  if (h.length()) Serial.println("Private message confirmed: " + h);
  else Serial.printf("private send failed: %s %s\n", client.lastErrorName(), client.lastErrorDetail().c_str());
}

void loop() {
  if (client.ready()) pollOnce();
  delay(15000);
}
