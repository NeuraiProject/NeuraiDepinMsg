// Test transport. The Python driver forwards requests to its disposable Core node.
#include "DepinClient.h"
#include <chrono>
#include <iostream>

using namespace depin;
using std::string;

struct PipeRpc : RpcTransport {
    RpcReply call(const string & method, const string & params, const string & id) override {
        std::cout << "{\"method\":\"" << method << "\",\"params\":" << params << ",\"id\":\"" << id << "\"}" << std::endl;
        RpcReply reply;
        reply.ok = bool(std::getline(std::cin, reply.body));
        return reply;
    }
};
struct WallClock : Clock {
    uint64_t unixMs() override {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }
    uint32_t monotonicMs() override {
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};
static void check(Err e, const DepinClient & client) {
    if (e != Err::Ok) {
        const auto & error = client.lastError();
        std::cerr << errName(e) << " " << error.detail << " " << error.rpc.reason << " " << error.rpc.message << std::endl;
        std::exit(1);
    }
}
int main() {
    string line;
    if (!std::getline(std::cin,line)) return 1;
    DynamicJsonDocument fixture(4096);
    if (deserializeJson(fixture,line)) return 1;
    PipeRpc rpc;
    WallClock clock;
    DepinClient legacy(rpc,clock), strict(rpc,clock);
    ClientConfig cfg;
    cfg.net = &NeuraiTest;
    cfg.expectedGenesis = fixture["genesis"].as<string>();
    cfg.serviceId = "regtest";
    cfg.token = cfg.pin.rootToken = fixture["token"].as<string>();
    cfg.pin.poolPubKeyHex = fixture["poolKey"].as<string>();
    check(legacy.begin(cfg,fixture["legacy"]),legacy);
    cfg.strictEcdsa = true;
    check(strict.begin(cfg,fixture["strict"]),strict);
    check(legacy.bootstrap(),legacy);
    check(strict.bootstrap(),strict);
    SendResult group,privateMsg;
    check(legacy.sendGroup("group from Legacy",group),legacy);
    check(strict.sendPrivate(legacy.address(),"private from strict ECDSA",privateMsg),strict);
    for (auto * reader : {&legacy, &strict}) {
        string cursor;
        for (const auto * expected : {&group,&privateMsg}) {
            ReceivePage page;
            check(reader->receivePage(cursor,1,page),*reader);
            if (page.messages.size() != 1 || page.messages.front().hash != expected->hash ||
                page.rejected || page.shouldContinue != (expected == &group)) return 1;
            const auto & content = page.messages.front().content;
            if (string(content.begin(),content.end()) != (expected == &group ? "group from Legacy" : "private from strict ECDSA")) return 1;
            cursor = page.nextCursor;
        }
        ReceivePage empty;
        check(reader->receivePage(cursor,1,empty),*reader);
        if (!empty.messages.empty() || empty.shouldContinue) return 1;
    }
}
