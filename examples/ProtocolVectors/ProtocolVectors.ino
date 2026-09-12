/*
 * ProtocolVectors — runs the DePIN Messaging Protocol 2 vectors (spec §13,
 * Neurai/contrib/depin/vectors.txt) on the ESP32 itself, without network,
 * and reports heap / stack / timing. This is the phase-1 acceptance sketch
 * of NeuraiDepinMsg: every check must print PASS.
 *
 * Validation target: ESP32-S3. Serial 115200. No Wi-Fi needed — the
 * ECIES *encryption* self-test therefore uses esp_fill_random() unseeded by
 * RF, which is fine for a test but NOT for production traffic (see
 * DepinCryptoMbedtls.cpp). Decryption and verification need no randomness.
 *
 * Keys are REGTEST vectors: never fund or reuse them.
 * Generated from test/fixtures/vectors.txt — do not edit the constants by hand.
 */
#include <Arduino.h>
#include <esp_heap_caps.h>
#include "NeuraiDepinMsg.h"
#include "DepinAuth.h"
#include "DepinReply.h"
#include "Message.h"
#include "Conversion.h"
#include "Hash.h"

static const char V_HOLDER_WIF[] PROGMEM =
  "cW8vy4nJbZZ4W4L8CsRZp22h3WeWrCXgNwrm1264wW8VAmzHMuJ4";
static const char V_HOLDER_PUBKEY[] PROGMEM =
  "032abff8246242d5d16a80148018d683ad5415edc1164ab1c3d90e57760bc5f0f3";
static const char V_HOLDER_ADDRESS[] PROGMEM =
  "tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n";
static const char V_REQ_PREIMAGE[] PROGMEM =
  "DEPIN-REQ|receive|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n|1730000000000";
static const char V_REQ_SIGNATURE[] PROGMEM =
  "IIMy0pTVnBwcxFYaqFsxaGbsNvXPuRbQ7Deey3kMIQ1jRhUZ+HQgoTfeDslbQ83yqyJ6vptnBa1DC31VqD74dhs=";
static const char V_GET_PREIMAGE[] PROGMEM =
  "DEPIN-GET|&TEST/SEC|tRERn8G265FxuHmiWVYtZ84ntQjW56BF8n|000102030405060708090a0b0c0d0e0f1011121314151"
  "61718191a1b1c1d1e1f";
static const char V_GET_SIGNATURE[] PROGMEM =
  "IB7YZLyXRnACLiZFCE4UIyYIfIwMsNqMLtzLuO5CdayuBZLDeXvp9PuYoBnUh84DOyuMPNt3Bvrbrb5yhlzdRd8=";
static const char V_POOL_PUBKEY[] PROGMEM =
  "03649c7a094c76b63995e60f891c13d9440b12b65b46ad8426cb153789e816b01b";
static const char V_POOL_ADDRESS[] PROGMEM =
  "tDudNSQstiVQu3Prbs7yFwbYtDrcU19eKJ";
static const char V_INFO_BODY[] PROGMEM =
  "7b22656e61626c6564223a747275652c22746f6b656e223a222654455354222c22636970686572223a224145532d3235362d"
  "47434d222c226d6178726563697069656e7473223a32302c226d61786d65737361676573697a65223a313032342c226d6573"
  "73616765657870697279686f757273223a3136382c226d6178706f6f6c73697a656d62223a3130302c226d65737361676573"
  "223a302c226d656d6f72797573616765223a302c226d656d6f727975736167656d62223a302c2270726f746f636f6c223a32"
  "2c22646570696e706f6f6c706b6579223a223033363439633761303934633736623633393935653630663839316331336439"
  "34343062313262363562343661643834323663623135333738396538313662303162222c22646570696e706f6f6c6b657961"
  "646472657373223a22744475644e5351737469565175335072627337794677625974447263553139654b4a222c2264657069"
  "6e77616c6c6574223a2277616c6c65742e646174227d";
static const char V_INFO_POOLSIG[] PROGMEM =
  "H8MOG9VPuYvSghphjmuIns5quiTry+AMrC4kMIXEGyxXQFArA3wnsXq3C8wyNWCLOYsNNNYJXfGen269pyOqp3g=";
static const char V_CHALLENGE_ENCRYPTED[] PROGMEM =
  "21031bae8e5d21da97921fde5b34b587fe675993c987127c9e866c6cb8d5499f59258dafef8621927216be40e33dc6f0319b"
  "89806c6db29367ee296808c019d3ce6d0ca950533d2cf123ad79acdd6ba19520ab57dad2b5464cdae78b98d4fb0091284cf0"
  "bdf59ea500c0481f53c8841506e00c0d985520c1a37c2f6a5cbbd01ba050ef0e568f47a2a5fab7778c1f886fd4bd4e875cca"
  "9d1fb4db252457006913a06e37e0b623de9c5a4adde4b067c9eb01c8d12daa260a43e5e3b63329bdc33451e41069223cec93"
  "f1b7e583c3f182dc8ff5b09a038eea23413472d55e940f5c5422dd43c5027bd20a215090be78996c9145e59f537b5391bd13"
  "f6724aed33a9d01a";
static const char V_CHALLENGE_PLAIN[] PROGMEM =
  "{\"challenge\":\"9bbd728c3e35285321c594a6925b537d743ad11da328163715363511deeae8ef\",\"expires_in\":30,\"typ"
  "e\":\"receive\"}";
static const char V_RECEIVE_ENCRYPTED[] PROGMEM =
  "2102412d44ae14acca0e0c74019da1f751a55f760033bc61385adea8f75ab140a229a64c586a20e3bc225421d3330ec9befa"
  "02fd3abad1b064f56776e3a2fd502e1d0bce752d03cfa5c53b7a25afd8d8b63dce0ec51882d2e8db32666dfb877cd4e42dd7"
  "49276523a0566f0535c4e4a07e89f6844ca96940d1e486e331d19f3823f39ac684b1c7ef860e6b9e0bde6f899f39854efb4f"
  "bf11fa56e1b587bffe77e3cba4763022ac6933997abafc87763cd72e477fea36aceb99bcaf090283024d2fc225f395a1c56a"
  "8701c8d12daa260a43e5e3b63329bdc33451e41069223c15aaf005a3967beba4089a8a654a82fe59186868cffa9e5dd2d2f8"
  "ea1e2cc1096615e176d8a31addf9c226ad394bbd537d367495b5d9586040e05033";
static const char V_RECEIVE_PLAIN[] PROGMEM =
  "{\"messages\":[],\"has_more\":false,\"next_challenge\":\"db3c27106853eafbb8fba74e72f66a5dd307d9a3edb0859eb5"
  "16f3d6f9b6e3bd\",\"next_expires_in\":300}";
static const char V_RECEIVE2_ENCRYPTED[] PROGMEM =
  "21038c2640bafe4807c70780014eea6cba4663bc44ca1c0cc5e6dc4167a53e920c40fd050460a3fdf5a0ef3513e7066f26ed"
  "3d15f60cdb4657fbf93ac2b01d410e2a7e9925e6b947eb98ca674130f6e3bb9b8c60f5f5b260bedcea63dc1ac83c2f789770"
  "67e317046e91f64eb0d6179e42bb0a4844136354fe94148cd716f9b111083d620d51439b601a46ecd42a595d71b54b599797"
  "37b7d8aa057e9527f2b3ecf6fd15a0df7915c44ef971da6483830ac91d5594c7b5d0a6f9639c2174b62d052b940a4156101d"
  "7d9e445e16c03b80bf1108eac5ec75b44db731a5bdaf32cc0adcf0a09c872169ffbaca6c43106dcc878a52c8043b471b71ef"
  "1e8b4b354129f86cb498be493a6999faea3242e9fa811e959841e15299da9b1361dfa0902530f5b0873b5f56dbed6a34cc21"
  "00b49732e84026956387226320cb0e4eee80164bc068fb2826529448133c1cc1f4468e3972fd7cf80680038e4fc6c6b4f02f"
  "7fe97f7a5ee4568e986ce0b1ff8d2c15f6e338fa654eb5b32fb83d9ceefd34c6c0cf2781493f0856e0fbb90442017845cafa"
  "3024f4165169eb53b3a20ca3c6801c1c5eb0d81e54a524c9aa528513a948f68379e988047be2c4bb45721dc35d2818c41a0f"
  "4618c8de8507da108b1f8312e2a958eb0be2db5816b7f03a2d98f7de142391146e88346ef26a97fcb4115dbf71bd4b4c0daa"
  "438336c508ac200cfd7572dc572063e3fd58fcbb4ecc729074dc86aafc4613ad4fd2fd0985fd5655b0b0b37b03f9d56d326a"
  "70cb2a2f8666712b1ab2c3ac068d42dc76c4c57d9ada89086dffd29fcc9e264313020e5f86e772a6511bd5c0bf49ac8642f7"
  "f696e31c92fda901a7f0d834dfe3206129a3a435279f611a9c74d5bac1deacc2b1c9d1ac39a7cd182e75d7e024d8ef348318"
  "4029691f1e87368445967556ead6125ea70745be1b774cca8ccee32e7a3ab9f185f6c3d595d132c67eb44c8e526e53b0618c"
  "a25ef2ea32f493b9860a8455b62f9d25b10eccb29e59102bb984896c8afc1c4d5390a9598304982412da5e1bf47964371745"
  "a4909ad42809878a641b69299baddc0413160f259cca0193fb01669eb322f78fbe99118d165a90884a7dd95d05b48879c816"
  "3a3e575012926f34bfb7ca71077b8368541799d9121f6e4a4234cf44738d62397914e4e551ceed4c41f5bb211d41fae4b256"
  "f314432a9db076fbd7772979b368f89589a489e0b613501555fa14b2690d6c158e256f1a219a3e964278220cd4cba01bb94e"
  "a2a6dfe3e76e08e0bc17439f9265c464c5ddf754d4889ebd167715e0a0ae36a1ef7ebe1e3118ddaefdea856ee318c95fde60"
  "046a32db52df37e72917b548e6e681e0764757c7cfc57135de9409b588a663eaa31c0dbbfcaa3d2b12f2776b996e81ef149d"
  "eae76ccf2cf5a683a0af161d2100e85004cdf8a45565897ba9089f4e5ac3ab2cf2c82827b5220565763f8584608fe559084b"
  "d9db1b8fa1923e7ede3feb9d9277dd8101c8d12daa260a43e5e3b63329bdc33451e41069223c8a651c619c8a3fe015267d43"
  "60be3d639b83034fb4a2f1a440c589189410a03ea2d96d3dc292244437314ac1b4e0d69e89f7bdb0c6f34bf56bfe5162";
static const char V_RECEIVE2_PLAIN[] PROGMEM =
  "{\"messages\":[{\"hash\":\"4e397239a092448ba9690e7383e316ebb9fcdccab4c3796f2e4647e34f1ed614\",\"token\":\"&TE"
  "ST/SEC\",\"sender\":\"tQPMWuhNSyFQnMzf8NgGD5RfN95J17G8hp\",\"timestamp\":1787377444,\"message_type\":\"group\","
  "\"encrypted_payload_hex\":\"21025e1412adc694b76b41f77ba6d5a19e737c9ec9c317efa0da0c9d6d732c534ea22f63985"
  "4b52a4af28fb1b37df0ce56f65d19d0c4fd5667f1f4ce1d18595a88e4a6284f1d88f9cfd9ba38379637b3360e02bf893cfba"
  "6b589dd64de3933fd0abf043be229f63ca6b48207135bacdfd24d8423c269ba2a22aecd92b9cfdaf2f150755e5d8550eec2d"
  "407e95d63586e0f2f9b32fd8b58268bb54584fee07dbb355b2e8fc8d12daa260a43e5e3b63329bdc33451e41069223c567a7"
  "b741bff039ebe95413fc54ea16d2cb3c5271403fbbdb37c401791000f9c120f73f9aa51f421a960bc25cd28b5fbed7c8a121"
  "6064a095434494b\",\"signature_hex\":\"304402200dc1f0e5d40ea8d78525d41e1d6a4a667cf03576d1052a65e2bbb613ea"
  "bd97d202203f3a1b31d9109795c6137049bcdc298a06d60daddf7b8b6b8ab626c0e20911c4\"}],\"has_more\":false,\"next"
  "_challenge\":\"a47fe319d2bfdca5a0bc9d70ee0f5bd505417c27391c345051c6bc0847a50c3f\",\"next_expires_in\":300"
  "}";
static const char V_SENDER_PUBKEY[] PROGMEM =
  "02f737ef588350e23ab39b8cd8599ac45431e7f5cc4bd5d5c0172ef44bf0470728";



static const char V_RECEIVE_NONCE[] PROGMEM =
  "9bbd728c3e35285321c594a6925b537d743ad11da328163715363511deeae8ef";
static const char V_CHALLENGE_POOLSIG[] PROGMEM =
  "IEVB0i5eNa1/E0L7yr99MdrVbnYd21MqpemILA0NShpGXBQXSH3PobiKDo5rO6lI1PHSpzgz62/C1vw3lckcHg8=";
static const char V_RECEIVE_POOLSIG[] PROGMEM =
  "HwuCWkrExACb3QnCMyYjNMuagzLxEwDDncrpoAqPx4mgcoi7aXjRkQ0nJsEkNF3+EgEt7mPdeqFAqdaZsYhaH7M=";

static int g_pass = 0, g_fail = 0;
static void report(bool ok, const char * what) {
  if (ok) g_pass++; else g_fail++;
  Serial.printf("[%s] %s\n", ok ? "PASS" : "FAIL", what);
}
static String P(const char * pm) { return String(FPSTR(pm)); }
static std::vector<uint8_t> H(const String & hex) {
  std::vector<uint8_t> out(hex.length() / 2 + 1);
  depin::Err e;
  size_t n = depin::hexDecode(hex.c_str(), hex.length(), out.data(), out.size(), &e);
  out.resize(e == depin::Err::Ok ? n : 0);
  return out;
}
static String jsonField(const String & json, const char * key) {
  String k = String("\"") + key + "\":";
  int p = json.indexOf(k);
  if (p < 0) return "";
  p += k.length();
  if (json[p] == '"') { int q = json.indexOf('"', p + 1); return json.substring(p + 1, q); }
  int q = p; while (q < (int)json.length() && json[q] != ',' && json[q] != '}') q++;
  return json.substring(p, q);
}

struct Meter {
  uint32_t t0; size_t free0;
  const char * name;
  Meter(const char * n) : name(n) { t0 = micros(); free0 = ESP.getFreeHeap(); }
  void done() {
    uint32_t dt = micros() - t0;
    Serial.printf("      %-28s %6lu us  heap now %6u  min ever %6u  largest block %6u\n",
                  name, (unsigned long)dt, (unsigned)ESP.getFreeHeap(),
                  (unsigned)ESP.getMinFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
  }
};

static void runVectors() {
  Serial.printf("heap at start: free %u, min %u, largest %u\n",
                (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
  report(depin::cryptoBackend() != NULL, "mbedTLS crypto backend registered");

  /* §13.1 keys */
  PrivateKey holder;
  report(depin::loadPrivateKey(std::string(P(V_HOLDER_WIF).c_str()), holder) == depin::Err::Ok, "holder WIF loads (regtest 0xef)");
  { uint8_t sec[33]; PublicKey p = holder.publicKey(); p.compressed = true; p.sec(sec, 33);
    report(String(depin::hexEncode(sec, 33).c_str()) == P(V_HOLDER_PUBKEY), "§13.1 WIF -> pubkey");
    report(depin::pubKeyMatchesAddress(p, std::string(P(V_HOLDER_ADDRESS).c_str())), "§13.1 pubkey <-> address"); }

  /* §13.2 signmessage (uNeurai Message.h) */
  { Meter m("signMessage DEPIN-REQ");
    char sig[NEURAI_MESSAGE_SIG_B64_LEN + 1];
    signMessageBase64(holder, P(V_REQ_PREIMAGE).c_str(), sig, sizeof(sig));
    m.done();
    report(P(V_REQ_SIGNATURE) == sig, "§13.2 DEPIN-REQ signature byte for byte");
    signMessageBase64(holder, P(V_GET_PREIMAGE).c_str(), sig, sizeof(sig));
    report(P(V_GET_SIGNATURE) == sig, "§13.2 DEPIN-GET signature byte for byte"); }

  /* §13.3 poolsig recovery */
  { String body = P(V_INFO_BODY);
    uint8_t h[32]; sha256((const uint8_t *)body.c_str(), body.length(), h);
    String pre = "DEPIN-RESP|depingetmsginfo|&TEST|||" + String(depin::hexEncode(h, 32).c_str());
    Meter m("recover poolsig");
    uint8_t pub[33]; int ok = recoverMessageSigner(P(V_INFO_POOLSIG).c_str(), pre.c_str(), pub);
    m.done();
    report(ok && String(depin::hexEncode(pub, 33).c_str()) == P(V_POOL_PUBKEY), "§13.3 poolsig recovers the pool key");
    report(verifyMessage(P(V_POOL_ADDRESS).c_str(), P(V_INFO_POOLSIG).c_str(), pre.c_str(), &NeuraiTest), "§13.3 poolsig verifies for the pool address"); }

  /* §13.3–§13.5 through DepinReply: container -> poolsig -> open (phase 2) */
  { PublicKey pool; depin::loadPublicKey(std::string(P(V_POOL_PUBKEY).c_str()), pool);
    std::string rpc = "{\"result\":{\"body\":\"" + std::string(P(V_INFO_BODY).c_str()) + "\",\"poolsig\":\"" + std::string(P(V_INFO_POOLSIG).c_str()) + "\"},\"error\":null,\"id\":\"t1\"}";
    depin::Pin pin; pin.serviceId = "test"; pin.rootToken = "&TEST"; pin.poolPubKeyHex = P(V_POOL_PUBKEY).c_str();
    depin::BootstrapResult b;
    Meter m("bootstrap RequirePin");
    depin::Err e = depin::bootstrap(rpc, "t1", depin::TrustMode::RequirePin, pin, pin.serviceId, &NeuraiTest, b);
    m.done();
    report(e == depin::Err::Ok && b.pinConfirmed && b.info.maxRecipients == 20, "§13.3 bootstrap with a full pin");
    depin::Pin wrong = pin; wrong.rootToken = "&OTHER";
    report(depin::bootstrap(rpc, "t1", depin::TrustMode::RequirePin, wrong, pin.serviceId, &NeuraiTest, b) == depin::Err::PoolSigInvalid, "wrong pinned root rejected before decoding");
    report(depin::bootstrap(rpc, "t1", depin::TrustMode::ExplicitTofu, depin::Pin(), "test", &NeuraiTest, b) == depin::Err::Ok && !b.pinConfirmed && b.candidate.rootToken == "&TEST", "TOFU candidate (unconfirmed)");
    std::string rpcCh = "{\"result\":{\"encrypted\":\"" + std::string(P(V_CHALLENGE_ENCRYPTED).c_str()) + "\",\"poolsig\":\"" + std::string(P(V_CHALLENGE_POOLSIG).c_str()) + "\"},\"error\":null,\"id\":\"t1\"}";
    depin::ReplyContext ch; ch.method = "depinchallenge"; ch.token = "&TEST/SEC"; ch.address = P(V_HOLDER_ADDRESS).c_str();
    std::string json;
    Meter m2("openReply bound (challenge)");
    e = depin::openReply(rpcCh, "t1", ch, depin::ReplyKind::Bound, pool, &holder, json);
    m2.done();
    report(e == depin::Err::Ok && json == std::string(P(V_CHALLENGE_PLAIN).c_str()), "§13.4 bound challenge reply opens");
    std::string rpcRx = "{\"result\":{\"encrypted\":\"" + std::string(P(V_RECEIVE_ENCRYPTED).c_str()) + "\",\"poolsig\":\"" + std::string(P(V_RECEIVE_POOLSIG).c_str()) + "\"},\"error\":null,\"id\":\"t1\"}";
    depin::ReplyContext rc = ch; rc.method = "depinreceivemsg"; rc.challenge = P(V_RECEIVE_NONCE).c_str();
    report(depin::openReply(rpcRx, "t1", rc, depin::ReplyKind::Bound, pool, &holder, json) == depin::Err::Ok && json == std::string(P(V_RECEIVE_PLAIN).c_str()), "§13.5 bound receive reply opens");
    depin::ReplyContext n8 = rc; n8.challenge = "";
    report(depin::openReply(rpcRx, "t1", n8, depin::ReplyKind::Bound, pool, &holder, json) == depin::Err::PoolSigInvalid, "N8 reply bound to its challenge");
    std::string sig;
    report(depin::signPreimage(holder, std::string(P(V_REQ_PREIMAGE).c_str()), sig) == depin::Err::Ok && sig == std::string(P(V_REQ_SIGNATURE).c_str()), "§13.2 DEPIN-REQ via DepinAuth"); }

  /* §13.4 / §13.5 ECIES */
  std::vector<uint8_t> pt;
  { std::vector<uint8_t> env = H(P(V_CHALLENGE_ENCRYPTED));
    Meter m("ecies decrypt (challenge)");
    depin::Err e = depin::eciesDecrypt(env.data(), env.size(), holder, pt);
    m.done();
    report(e == depin::Err::Ok && String((const char *)pt.data(), pt.size()) == P(V_CHALLENGE_PLAIN), "§13.4 challenge reply decrypts");
    /* N3 (payload tag) / N4 (entry tag) / N5 (wrong key) */
    depin::EciesView v; depin::eciesParse(env.data(), env.size(), v);
    std::vector<uint8_t> n3 = env; n3[(v.payload - env.data()) + v.payloadLen - 1] ^= 1;
    report(depin::eciesDecrypt(n3.data(), n3.size(), holder, pt) == depin::Err::PayloadAuthFailed, "N3 payload tag rejected");
    std::vector<uint8_t> n4 = env; n4.back() ^= 1;
    report(depin::eciesDecrypt(n4.data(), n4.size(), holder, pt) == depin::Err::KeyUnwrapFailed, "N4 entry tag rejected");
    uint8_t other[32]; memset(other, 0x42, 32); PrivateKey stranger(other, true, &NeuraiTest);
    report(depin::eciesDecrypt(env.data(), env.size(), stranger, pt) == depin::Err::NotForRecipient, "N5 wrong recipient rejected"); }
  { std::vector<uint8_t> env = H(P(V_RECEIVE_ENCRYPTED));
    report(depin::eciesDecrypt(env.data(), env.size(), holder, pt) == depin::Err::Ok &&
           String((const char *)pt.data(), pt.size()) == P(V_RECEIVE_PLAIN), "§13.5 receive reply (empty) decrypts"); }
  String receive2;
  { std::vector<uint8_t> env = H(P(V_RECEIVE2_ENCRYPTED));
    depin::Limits lim = depin::defaultLimits(); lim.maxContent = 4096;
    Meter m("ecies decrypt (1 message page)");
    depin::Err e = depin::eciesDecrypt(env.data(), env.size(), holder, pt, lim);
    m.done();
    if (!pt.empty()) receive2 = String((const char *)pt.data(), pt.size());
    report(e == depin::Err::Ok && receive2 == P(V_RECEIVE2_PLAIN), "§13.5 receive reply (1 message) decrypts"); }

  /* §13.6 message: normalise from RPC fields, verify, decrypt */
  { String row = receive2.substring(receive2.indexOf('{', 1));
    DepinReceivedMessage rm;
    Meter m("fromRpcFields + verify");
    depin::Err e = NeuraiDepinMsg::fromRpcFields(jsonField(row, "token"), jsonField(row, "sender"),
        jsonField(row, "timestamp").toInt(), jsonField(row, "message_type"),
        jsonField(row, "encrypted_payload_hex"), jsonField(row, "signature_hex"), jsonField(row, "hash"), rm);
    report(e == depin::Err::Ok, "§13.6 row normalises and hash matches");
    e = NeuraiDepinMsg::verifyDepinMessage(rm, P(V_SENDER_PUBKEY));
    m.done();
    report(e == depin::Err::Ok && rm.verified, "§13.6 DER verifies with the sender key");
    std::vector<uint8_t> content;
    report(NeuraiDepinMsg::decryptPayload(jsonField(row, "encrypted_payload_hex").c_str(), holder, content) == depin::Err::Ok &&
           String((const char *)content.data(), content.size()) == "Hello from the spec", "§13.6 content decrypts");
    /* N6 / N7 */
    DepinReceivedMessage n6 = rm; n6.msg.signature.back() ^= 1;
    report(NeuraiDepinMsg::verifyDepinMessage(n6, P(V_SENDER_PUBKEY)) != depin::Err::Ok, "N6 tampered DER rejected");
    DepinReceivedMessage n7;
    report(NeuraiDepinMsg::fromRpcFields(jsonField(row, "token"), jsonField(row, "sender"),
        jsonField(row, "timestamp").toInt() + 1, jsonField(row, "message_type"),
        jsonField(row, "encrypted_payload_hex"), jsonField(row, "signature_hex"), jsonField(row, "hash"), n7) == depin::Err::HashMismatch,
        "N7 changed field -> hash mismatch");
    report(NeuraiDepinMsg::verifyDepinMessage(rm, P(V_HOLDER_PUBKEY)) == depin::Err::BadPubKey, "sender key must match the sender address"); }

  /* build + decrypt round trip on-device (uses esp_fill_random) */
  { DepinParams p;
    p.token = "&TEST/SEC"; p.senderAddress = P(V_HOLDER_ADDRESS); p.senderPubKey = P(V_HOLDER_PUBKEY);
    p.privateKey = P(V_HOLDER_WIF); p.timestamp = 1787377444; p.message = "Hello from the ESP32"; p.messageType = "group";
    Meter m("buildDepinMessage (1 rcpt)");
    DepinMessageResult r = NeuraiDepinMsg::buildDepinMessage(p);
    m.done();
    report(r.ok(), "build message on device");
    DepinReceivedMessage back;
    report(NeuraiDepinMsg::parseDepinMessage(r.hex, back) == depin::Err::Ok && back.hash == r.messageHash, "wire parse round trip");
    report(NeuraiDepinMsg::verifyDepinMessage(back, P(V_HOLDER_PUBKEY)) == depin::Err::Ok, "own signature verifies");
    String plain = NeuraiDepinMsg::decryptPayload(r.encryptedPayloadHex.c_str(), P(V_HOLDER_WIF));
    report(plain == "Hello from the ESP32", "own content decrypts");
    Meter w("wrapMessageForServer");
    String env = NeuraiDepinMsg::wrapMessageForServer(r.hex, P(V_POOL_PUBKEY));
    w.done();
    report(env.length() > 0, "pool envelope built"); }

  Serial.printf("heap at end: free %u, min ever %u, largest block %u; task stack high-water %u bytes\n",
                (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(), (unsigned)ESP.getMaxAllocHeap(),
                (unsigned)uxTaskGetStackHighWaterMark(NULL));
  Serial.printf("\n%d PASS, %d FAIL\n", g_pass, g_fail);
}

static void vectorsTask(void *) {
  runVectors();
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1500);
  Serial.println("\nNeuraiDepinMsg ProtocolVectors (protocol 2, spec §13)");
  /* 16 KB stack: secp256k1 + AES-GCM comfortably; the loop task's 8 KB is tight */
  if (xTaskCreatePinnedToCore(vectorsTask, "vectors", 16384, NULL, 1, NULL, 1) != pdPASS)
    Serial.println("0 PASS, 1 FAIL: cannot allocate vectors task");
}

void loop() { delay(1000); }
