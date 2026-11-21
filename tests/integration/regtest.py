"""Exercise the portable ESP32 client against two disposable Core wallets."""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(os.environ["NEURAI_SOURCE"]) / "test/functional"))
from feature_depin_ecdsa import DepinECDSATest, TOKEN
from test_framework.authproxy import JSONRPCException
from test_framework.util import sync_blocks


class MessagingTest(DepinECDSATest):
    def run_test(self):
        self.clients()
        self.primary.generate(432)
        sync_blocks(self.nodes)
        alice = self.primary.getnewaddress()
        bob = self.secondary.getnewaddress()
        self.reveal(alice, self.primary)
        self.reveal(bob, self.secondary)
        self.primary.issue(TOKEN, 100, alice)
        self.mine()
        self.primary.transfer(TOKEN + "!", 1, alice)
        self.mine()
        self.primary.transferfromaddress(TOKEN, alice, 10, bob, "", 0, "", alice)
        self.mine()

        fixture = dict(genesis=self.primary.getblockhash(0), token=TOKEN,
                       poolKey=self.legacy_client.bootstrap()[1]["depinpoolpkey"],
                       legacy=self.primary.dumpprivkey(alice), strict=self.secondary.dumpprivkey(bob))
        with subprocess.Popen([os.environ["DEPIN_CLIENT_TEST"]], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True) as client:
            client.stdin.write(json.dumps(fixture) + "\n")
            client.stdin.flush()
            for line in client.stdout:
                request = json.loads(line)
                try:
                    result = getattr(self.primary, request["method"])(*request["params"])
                    response = dict(id=request["id"], result=result, error=None)
                except JSONRPCException as exc:
                    response = dict(id=request["id"], result=None, error=exc.error)
                client.stdin.write(json.dumps(response) + "\n")
                client.stdin.flush()
            assert client.wait(timeout=10) == 0


if __name__ == "__main__":
    MessagingTest().main()
