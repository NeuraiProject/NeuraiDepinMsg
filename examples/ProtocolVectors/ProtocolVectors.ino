// Offline known-answer test from Neurai Core's depin_format3.json.
#include <NeuraiDepinMsg.h>

void setup() {
    Serial.begin(115200);
    DepinReceivedMessage message;
    const String genesis = "000000c710413a4265a996d30c86043aedef6a563900f1bc43fea61d5b2dc77d";
    const String address = "tLfoB6752dvwWHiUA7Jg5iWKWCmS9Y1BAB";
    depin::Err error = NeuraiDepinMsg::fromRpcFields(genesis, "&TEST/A", address, 1794736920, "group",
        "0003210259ca1950ba0193e12db24ea7ad73b09483442c485e247d6e9125f1dd4c81df6a35289d8165f2c5ab898825634a9927b6c01bb46e3988985d87c18525e27b3dc12d9f2eda471fb42a5a314fb22bbd0b2f10bd24ae0e67f40c7ba6b8a2e7e44c8b4effb4224a16175d5c38d78b0fa80300580f8ac34cf57a74f1ade312a59606b40f7f9d813c5175ee7d276cefef25a440676eaec49bfde290232b040564361f4a4fdef46e616a56de3968efb448eb0fc6aacbd3cd654feed181f4d58567b6b78f960096c4cf14c55029402faaa84ef1b1ca0e301e76c73c3a12a7a96c395e31cf8513877a8de640ad2c7faeb1e2b38c4a299671d62a367fa81918bbb0f115200ef394b2d19d1ddb56e90580ad35cc158be7df2903c99bd8f62c707a2df4164b849b9f297961d35f263575d3ec4661d256d0fce2d73cb6c231bf01b92234a49ea8e4566a3d536a8a47a74b125c19a6f7dca97a750003278946548116b313d56a4b5de368f3e26feab7071202c541d6bd6d0c",
        "3045022100a10231abbfaeb019f95b008808fd82575a0114a5d94d869a2bfc44d1bad75601022008d7d2f967f74fe0c2909f72be6582bf2bbd83d754a484aef8aafb90280a75d3",
        "45e6e51a2af2284c3b5618e34e41315ac85cac1171b37d339e58c679a5794339", message);
    if (error == depin::Err::Ok) error = NeuraiDepinMsg::verifyDepinMessage(message, "036361e26b23bfe63c5208216a8252eecfe75de75d46fbb1ab73e3bcfff2e3c3a0");
    bool passed = error == depin::Err::Ok && NeuraiDepinMsg::decryptPayload(message, address,
        "48d32c92e64486d1cd57e1952c0f76ba36e48d0ba10d1db0c4ebc981666c9ed5") == "Reunión a las 10";
    Serial.println(passed ? "Format 3 vector passed" : "Format 3 vector failed");
}

void loop() {}
