from bip_utils import Bip39SeedGenerator, Bip44Changes, Bip84, Bip84Coins
from lib.bitcoin_lib import PrivateKey


class PrivKey:
    def __init__(self, mnemonic):
        # generate seed from mnemonic
        self.seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

        # generate  root key from seed
        self.bip_obj_mst = Bip84.FromSeed(self.seed_bytes, Bip84Coins.BITCOIN_TESTNET)

        # generate BIP44 account keys: m/84'/1'
        self.bip_obj_coin = self.bip_obj_mst.Purpose().Coin()

        # generate BIP44 account keys: m/84'/1'/0'
        self.bip_obj_acc = self.bip_obj_coin.Account(0)

        # generate BIP44 chain keys: m/84'/1'/0'/0
        self.bip_obj_change = self.bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)

        # generate private key
        self.priv_key = PrivateKey(int.from_bytes(self.bip_obj_change.PrivateKey().Raw().ToBytes(), "little"), compressed=True, testnet=True)

    def get_key(self):
        return self.priv_key