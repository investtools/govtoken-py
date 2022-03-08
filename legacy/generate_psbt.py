from pprintpp import pprint

from bitcointx import select_chain_params
from bitcointx.core.script import SIGHASH_ALL, CScript, OP_0
from bip_utils import Bip39SeedGenerator, Bip44Changes, Bip84, Bip84Coins


from lib.psbt import Creator, Updater
from lib.bitcoin_lib import hash160
from lib.utils import *

select_chain_params('bitcoin/testnet')

txo_tx_hexa = "02000000000101a05f2b51edaa0134837a4caef4f1342bd0a9313dfb90cf4f41ebea1fe0d63d560200000000fdffffff0310270000000000001600143420b001e0f255e5291edfa3c6bf8dc1322b163011270000000000001600143420b001e0f255e5291edfa3c6bf8dc1322b16302fa3050000000000160014896de572ea342f481063ca578697a9c85a007c300247304402205ce5b9900039387fb5bba5ff4342058604954a56f367703c9b8091c1fad22849022043b16ab0993b3e57752dc336d33ff2a71920977c84cc896583c42d42fe374ccf0121020d71f993fe49a72742f11fd8ea55e5b5bc70ef28d33a5bcd0eb66c2bd39481980e082000"
mnemonic = 'whale interest attitude humor sadness trick lizard liquid diesel trigger goose ignore'
txo = "957ff644403f4a0446f06442ec11e58f4fb6ba1d4198c43b43e17a0ae0af22e0"
vout = 1
path = "m/84'/1'/0'/0"
bip32_path = "m/827166'/1'/0" # for RGB change

# generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

# generate  root key from seed
bip_obj_mst = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN_TESTNET)

# generate BIP44 account keys: m/84'/1'
bip_obj_coin = bip_obj_mst.Purpose().Coin()

# generate BIP44 account keys: m/84'/1'/0'
bip_obj_acc = bip_obj_coin.Account(0)

# generate BIP44 chain keys: m/84'/1'/0'/0
bip_obj_change = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)


# get first address: m/84'/1'/0'/0/0
first_add_index = bip_obj_change.AddressIndex(0)
first_add = bip_obj_change.AddressIndex(0).PublicKey().ToAddress()

# get master fingerprint
master_fingerprint = bip_obj_change.PublicKey().m_pub_key.FingerPrint().ToBytes()
master_fingerprint_output = bip_obj_change.AddressIndex(0).PublicKey().m_pub_key.FingerPrint().ToBytes()


# get public key
pub_key = bip_obj_change.PublicKey()
pub_key_hex = pub_key.RawCompressed().ToHex()
print("pub_key_hex:", pub_key_hex)
pub_key_bytes = pub_key.RawCompressed().ToBytes()

# # get 1st address public key
first_address_pub_key = bip_obj_change.AddressIndex(0).PublicKey()
first_address_pub_key_hex = first_address_pub_key.RawCompressed().ToHex()
first_address_pub_key_bytes = first_address_pub_key.RawCompressed().ToBytes()

# # get master fingerprint from 1st address
# master_fingerprint = bip_obj_change.AddressIndex(0).PublicKey().m_pub_key.FingerPrint().m_fprint


# generate bip32_derivs
bip32_derivs = [
    {
        "pub_key": pub_key,
        "pub_key": pub_key_hex,
        "master_fingerprint": master_fingerprint,
        "path": path,
    }
]

#generate script_pubkey
script_pub_key = CScript([OP_0, hash160(pub_key_bytes)])
first_address_script_pub_key = CScript([OP_0, hash160(first_address_pub_key_bytes)])

#amount payed
amount = 9600

# psbt inputs
inputs = [(bytes.fromhex(txo), vout)]

# psbt outputs
outputs = [(int(amount), first_address_script_pub_key)]

# create psbt
creator = Creator(inputs, outputs)
psbt = creator.serialized()

# update psbt
updater = Updater(psbt)
updater.add_input_pubkey(input_index=0, pubkey=pub_key_bytes, masterkey_fingerprint=master_fingerprint, bip32_path=path_to_bytes(path))
updater.add_witness_utxo(input_index=0, utxo=bytes.fromhex(txo_tx_hexa), utxo_index=vout)
updater.add_bip32_derivs(derivs=bip32_derivs)
updater.add_sighash_type(input_index=0, sighash=SIGHASH_ALL)
updater.add_output_pubkey(output_index=0, pubkey=pub_key_bytes, masterkey_fingerprint=master_fingerprint, bip32_path=path_to_bytes(path)) # obrigatorio para o RGB (erro missing pubkey for output #0)
# updater.add_output_witness_script(output_index=0, script=script_pub_key) # da erro no RGB (LockScriptParserError)
print("updater")
pprint(updater.psbt.maps)
# export psbt
newFile = open("psbt.hex", "wb")
newFileByteArray = bytearray(updater.psbt.serialize())
is_written = newFile.write(newFileByteArray)
print("Written:", is_written)








