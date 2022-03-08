import hashlib
import struct
from binascii import unhexlify, hexlify
from bitcointx.core import CMutableTransaction, CTransaction
from bitcointx.core.script import SIGHASH_ALL, CScriptWitness, SignatureHash, RawSignatureHash, SIGVERSION_WITNESS_V0, standard_witness_v0_scriptpubkey
from btclib.bip32.key_origin import decode_from_bip32_derivs
from btclib.psbt.psbt_out import PsbtOut
from btclib.utils import bytes_from_octets
from pprintpp import pprint
from bitcointx import select_chain_params
from bitcointx.core.key import KeyStore
from bitcointx.core.psbt import PartiallySignedTransaction
from bitcointx.wallet import CCoinExtKey 

from bip_utils import Bip39SeedGenerator, Bip44Coins, Bip44, Bip44Changes, Bip84
from btclib.psbt.psbt import Psbt, finalize_psbt
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.script import Command, Script, parse, serialize
#from btclib.tx.tx_in import OutPoint, TxIn
#from btclib.tx.tx_out import TxOut
# from bitcoin import SelectParams
from bitcointx.core.script import CScript, OP_0, RawBitcoinSignatureHash, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, CScriptOp
#from bitcoin import b2x, b2lx, lx, COIN, COutPoint, CTxOut, CTxIn, CMutableTransaction
from binascii import unhexlify
from io import BytesIO
from lib.psbt import (
    psbt,
    Creator,
    Updater,
    Signer,
    Combiner,
    Input_Finalizer,
    Transaction_Extractor
)
from lib.bitcoin_lib import PrivateKey, hash160, int_to_little_endian, little_endian_to_int, Tx, TxIn, TxOut

from lib.cryptos.ecdsa import sign, verify


from base64 import b64encode


select_chain_params('bitcoin/testnet')
#SelectParams('testnet')

# random mnemonic for test, will be deprecated
mnemonic = 'whale interest attitude humor sadness trick lizard liquid diesel trigger goose ignore'
txo_1 = "cd4855ca6428de0ac7a6a96334cdeafe69e785e17a2c8e8d65d8f04a510ed11f"
txo_tx_hexa = "0200000000010239bf97d670200a17fbffb33488657db051def6ec508512fba89f4aaacf8bb41e0000000000fdffffffaf79d7f099f2955247f03101a7096ec86f5cba953c476679b91901dc9a6a36350000000000fdffffff051027000000000000160014a3919d73f91de9d16b99f2a6defe6f0903be5fc41127000000000000160014a3919d73f91de9d16b99f2a6defe6f0903be5fc412270000000000001600143420b001e0f255e5291edfa3c6bf8dc1322b163013270000000000001600143420b001e0f255e5291edfa3c6bf8dc1322b1630844700000000000016001499dedfa8555ef656a4e6a529429a83550ff065eb0247304402202489eba39e7ea9a245c4d364188952ab0e75aa12c3446ec3a9531f779f821c11022037ccdb922c191ad96f2aa33632bce2a8fce8f67b589a6bcbc7c38518b6dda0c50121026ba8d51b6d6120161b4c0ac6eeefe322c1cd3b1546da251c759c956222213f9e02473044022012ac84f80d2a2b4ccee923530c47a5e7355c1d455ad684898546a3675531912702207262304b59e3f0e599b0f67da6f2977026adf51e965a9d802dc2a633388cee5c0121026ba8d51b6d6120161b4c0ac6eeefe322c1cd3b1546da251c759c956222213f9efaf81e00"
vout_1 = 2
path = "m/84'/1'/0'/0"
# path = "m/" 

# generate seed from mnemonic
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
# generate  root key from seed
bip_obj_mst = Bip84.FromSeed(seed_bytes, Bip44Coins.BITCOIN_TESTNET)
#master_priv_wif = bip_obj_mst.PrivateKey().ToWif()
#master_priv_ext = bip_obj_mst.PrivateKey().ToExtended()

#print("Master key (bytes): %s" % bip_obj_mst.PrivateKey().Raw().ToHex())
#print("Master key (extended): %s" % bip_obj_mst.PrivateKey().ToExtended())
#print("Master key (WIF): %s" % bip_obj_mst.PrivateKey().ToWif())
# Print public key in extended format
#print("Pub key extended: %s" % bip_obj_mst.PublicKey().ToExtended())
# Print public key in raw uncompressed format
#print("Pub key uncompressed: %s" % bip_obj_mst.PublicKey().RawUncompressed().ToHex())
# Print public key in raw compressed format
#print("Pub key compressed: %s" % bip_obj_mst.PublicKey().RawCompressed().ToHex())

# generate BIP44 account keys: m/84'/1'
bip_obj_coin = bip_obj_mst.Purpose().Coin()
# generate BIP44 account keys: m/84'/1'/0'
bip_obj_acc = bip_obj_coin.Account(0)
# generate BIP44 chain keys: m/84'/1'/0'/0
bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
# get first address: m/84'/1'/0'/0/0
a = bip_obj_chain.AddressIndex(0)
first_add = bip_obj_chain.AddressIndex(0).PublicKey().ToAddress()
#print("FIRST ADDRESS PRIVATE KEY", a.PrivateKey().Raw().ToHex())
#print("FIRST ADDRESS PUBLIC KEY", a.PublicKey().RawCompressed().ToHex())
#print("FIRST ADDRESS", first_add)
#print("fingerprints", a.PublicKey().m_fprint)

# get master fingerprint
# m/84'/1'/0'/0 bip32_derivs
#print(bip_obj_acc.PublicKey().RawCompressed().ToHex()[-8:])
master_fingerprint = bip_obj_chain.PublicKey().m_fprint

bip32_derivs = [
    {
        "pub_key": bip_obj_chain.PublicKey().RawCompressed().ToHex(),
        "master_fingerprint": master_fingerprint,
        "path": path,
    }
]

#pprint(bip32_derivs)


# get master fingerprint
# m/84'/1'/0' bip32_derivs
# bip_obj_coin_fingerprint = bip_obj_coin.PublicKey().m_fprint
# bip_obj_acc_path = "m/84'/1'/0'"
# bip_obj_acc_bip32_derivs = [
#     {
#         "pub_key": bip_obj_acc.PublicKey().RawCompressed().ToHex(),
#         "master_fingerprint": bip_obj_coin_fingerprint,
#         "path": path,
#     }
# ]

# pprint(bip_obj_acc_bip32_derivs)


# get hd_key_path

# hd_key_paths = decode_from_bip32_derivs(bip32_derivs)
# pprint(hd_key_paths)

#SCRIPTPUBKEY

#publickey = bytes.fromhex(a.PublicKey().RawCompressed().ToHex())
#print('PUBKEYS BEGIN')
#print(a.PublicKey().RawCompressed().ToHex())
#print(type(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
#print('PUBKEY END')
publickey = bytes.fromhex(bip_obj_chain.PublicKey().RawCompressed().ToHex())
s = hashlib.new('sha256',    publickey).digest()
r = hashlib.new('ripemd160', s        ).digest()

txout_scriptPubKey = CScript([OP_0, r])

#print(bytes.hex(r))
#print(bytes.hex(txout_scriptPubKey))


# Outputs
scriptPubKey_1 = txout_scriptPubKey
amount_1 = 9600 
# Inputs
utxo_1 = bytes.fromhex(txo_1)
index_1 = vout_1
ins = [(utxo_1, index_1)]
outs = [(int(amount_1), scriptPubKey_1)]
# outs = [(int(amount_1), b"")] # testando sem output
creator = Creator(ins, outs)
#pprint(creator)
test_psbt = creator.serialized()
#pprint(test_psbt)
updater_test = Updater(test_psbt)
pubkey_1 = publickey
#print('PUBKEY_1', pubkey_1)
fingerprint_1 = master_fingerprint

def integer_array_to_hex_string(arr):
    # convert integer array to hex string 8 bytes at a time little endian encoding
    arr_little_endian = []
    for item in arr:
        arr_little_endian.append(item.to_bytes(4, byteorder='little'))
        # print(arr_little_endian)
    
    bytes_little_endian = b''.join(arr_little_endian)

    return bytes_little_endian

def integer_array_to_hex_string_BE(arr):
    # convert integer array to hex string 8 bytes at a time little endian encoding
    arr_big_endian = []
    for item in arr:
        arr_big_endian.append(item.to_bytes(2, byteorder='big'))
        # print(arr_little_endian)
    
    bytes_big_endian = b''.join(arr_big_endian)

    return bytes_big_endian

#new_path = "42'/0'/0'/0/1"
def path_to_bytes(path):
    # split bitcoin bip44 derivation path string by separator "/"
    # add integer 2147483648 to it if each item ends with "'"
    # and convert to hex string joining each item with ""
    # example: "44'/0'/0'/0/0" -> "0x8000002C80000000800000000000000000000000"
    # example: "42'/0'/0'/0/1" -> "0x8000002A80000000800000000000000000000001"
    # example: "47'/0'/0'/1/0" -> "0x8000002F80000000800000000000000100000000"
    path_split = path.split("/")
    path_split = path_split[1:]
    path_int = []
    for item in path_split:
        if item[-1] == "'":
            path_int.append(int(item[:-1]) + 2147483648)
        else:
            path_int.append(int(item))
        pprint (path_int)
    # convert integer array to bytes
    # [2147483692, 2147483649, 2147483648, 0] -> b'\x80\x00\x00\x2c\x80\x00\x00\x01\x80\x00\x00\x00\x00\x00\x00\x00'
    path_bytes = integer_array_to_hex_string(path_int)

    # path_hex = "8000002C"
    return path_bytes

path_1 = path_to_bytes(path)
#pprint(path_1)
#print(type(pubkey_1))
#pprint(pubkey_1)
#pprint(fingerprint_1)


updater_test.add_input_pubkey(input_index=0, pubkey=pubkey_1, masterkey_fingerprint=fingerprint_1, bip32_path=path_1)
updater_test.add_witness_utxo(input_index=0, utxo=bytes.fromhex(txo_tx_hexa), utxo_index=vout_1)
updater_test.add_bip32_derivs(derivs=bip32_derivs)
updater_test.add_sighash_type(input_index=0, sighash=SIGHASH_ALL)

# bip_obj_mst
# bip_obj_coin
# bip_obj_acc
# bip_obj_chain
# a
updater_test.add_output_pubkey(output_index=0, pubkey=pubkey_1, masterkey_fingerprint=fingerprint_1, bip32_path=path_to_bytes("m/827166'/1'/0"))
# updater_test.add_output_pubkey(output_index=0, pubkey=bytes.fromhex(a.PublicKey().RawCompressed().ToHex()), masterkey_fingerprint=a.PublicKey().m_fprint, bip32_path= path_to_bytes("m/84'/1'/0'/1/0"))
# updater_test.add_output_witness_script(output_index=0, script=scriptPubKey_1)
#updater_test.add_sighash_type(0, SIGHASH_ALL)

print_psbt = Psbt.parse(updater_test.psbt.serialize()).to_dict()

# print_psbt['tx']['vout'][0]['addresses'] = [first_add]
# print_psbt['tx']['vout'][0]['network'] = 'testnet'
#print_psbt['inputs'][0]['non_witness_utxo'] = utxo_1
print_psbt['fee'] = 200
#pprint(bytes.hex(updater_test.psbt.serialize()))
#print('NEW PSBT OFICIAL')
#pprint(print_psbt.tx.vout[0].network)
#pprint(print_psbt)
#pprint(updater_test.psbt.get_as_b64())
#print('NEW PSBT OFICIAL')

new_psbt = Psbt.from_dict(print_psbt)
#print_aux = new_psbt.to_dict()
#pprint(print_aux)

#print("PSBT SIGNER")
#pprint(psbt_to_sign.psbt)

newFile = open("psbt.hex", "wb")
newFileByteArray2 = bytearray(new_psbt.serialize())
is_written = newFile.write(newFileByteArray2)
#END OF PSBT ORIGINAL

# BEGIN OF PSBT GENERATED BY RGB
print('RGB TRANSACTION')
transaction_file = open('rgb_gen/transaction.tx', 'rb')
transaction = transaction_file.read()
#pprint(b64encode(transaction).decode("utf-8"))
transaction_dict = Psbt.parse(transaction).to_dict()
pprint(transaction_dict)

print('SIGNING')

prev_out = transaction_dict['tx']['vin'][0]['prev_out']
input_amount = transaction_dict['inputs'][0]['witness_utxo']['value']
scriptPubKey_2 = CScript(bytes.fromhex(transaction_dict['inputs'][0]['witness_utxo']['scriptPubKey']))
pubkey_2 = transaction_dict['inputs'][0]['bip32_derivs'][0]['pub_key']
amount = transaction_dict['tx']['vout'][0]['value']
txid = prev_out['txid']
vout = prev_out['vout']
#txin = CTxIn(COutPoint(lx(txid), vout))
#txout = CTxOut(int(float(amount)*10**8), scriptPubKey_2)
#tx = CMutableTransaction([txin], [txout])
sighash_type = transaction_dict['inputs'][0]['sign_hash']
#sighash = SignatureHash(scriptPubKey_2, tx, 0, sighash_type, amount=int(float(input_amount)*10**8), sigversion=SIGVERSION_WITNESS_V0)
#sighash = SignatureHash(script=scriptPubKey_1, txTo=tx, inIdx=0, hashtype=SIGHASH_ALL, amount=int(float(input_amount)*10**8), sigversion=SIGVERSION_WITNESS_V0)
#sighash =RawBitcoinSignatureHash( scriptPubKey_1, tx, 0, SIGHASH_ALL, amount=int(float(input_amount)*10**8), sigversion=SIGVERSION_WITNESS_V0)
#pprint(little_endian_to_int(sighash[-1:]))

#part_signed_psbt = psbt_to_sign.add_partial_signature(sighash, bytes.fromhex(pubkey_2))
#print('TXOUT SCRIPT', bytes.hex(txout_scriptPubKey))
#print('SCRIPT 2', bytes.hex(scriptPubKey_2))

# REF: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
#scriptPK = CScript([CScriptOp(0x19), OP_DUP, OP_HASH160, CScriptOp(0x14), r, OP_EQUALVERIFY, OP_CHECKSIG])
# = CScript([OP_DUP, OP_HASH160, r, OP_EQUALVERIFY, OP_CHECKSIG])
#witness_program = scriptPK.witness_program()
#print('IS P2PKH', witness_program.is_p2pkh()) #FALSE
#print('IS SCRIPT PUBKEY', witness_program.is_witness_scriptpubkey()) #FALSE
#print('WITNESS', witness_program)
witness_program =  scriptPubKey_2.witness_program()
witness_program = txout_scriptPubKey.witness_program()
#scriptPubKey_2 = txout_scriptPubKey
#witness_script = CScriptWitness(witness_)
#print('TXO WITNESS', witness_program)
txin = TxIn(bytes.fromhex(prev_out['txid']), 0, scriptPubKey_2, 0, witness_program=witness_program, value=int(float(input_amount)*10**8))
txout = TxOut((int(float(amount)*10**8)), script_pubkey=scriptPubKey_2)
tx_to_sign = Tx(version=2, tx_ins=[txin], tx_outs=[txout], locktime=0, testnet=True)
priv_key = PrivateKey(int.from_bytes(bip_obj_chain.PrivateKey().Raw().ToBytes(), "big"), compressed=True, testnet=True)
#print('PRIV KEY', bip_obj_chain.PrivateKey().ToWif())
#print('priv_key', priv_key.wif())
#print('PUB KEY', bip_obj_chain.PublicKey().RawCompressed().ToHex())
print('PUB KEY', pubkey_2)
print('PUB KEY H160', hash160(bytes(pubkey_2, 'utf-8')))
print('SCRIPT PUB KEY', bytes.hex(scriptPubKey_2))
print('SCRIPT PUB KEY', bytes.hex(txout_scriptPubKey))

#print('WITNESS SCRIPT', witness_script)
#was_signed = tx_to_sign.sign_input(0, priv_key, SIGHASH_ALL, compressed=True)
was_signed = tx_to_sign.sign_input(0, priv_key, SIGHASH_ALL, compressed=True, redeem_script=scriptPubKey_2)
#print(transaction)
#tx_to_sign2 = Tx.parse(transaction)
#print(tx_to_sign2)
#was_signed2 = tx_to_sign2.sign_input(0, priv_key, SIGHASH_ALL, compressed=True, redeem_script=witness_program)

print('SIGNED INPUT')
print(was_signed)
sec = tx_to_sign.tx_ins[0].sec_pubkey(0)
der = tx_to_sign.tx_ins[0].der_signature(0)
z = tx_to_sign.sig_hash_bip143(0, der[1])
print(z)
new_sig = z.to_bytes(len(str(z)), 'little')

psbt_to_sign = Signer(transaction)
#print(type(pubkey_2), type(sec))
psbt_to_sign.add_partial_signature(der, sec, 0)
#pprint(bytes.hex(tx_to_sign.serialize_segwit()))
#pprint(Psbt.parse(bytes.fromhex("70736274FF"+bytes.hex(tx_to_sign.serialize_segwit()))).to_dict())

# TESTING PUBKEY AFTER RGB TRANSFER
#print('TEST PUBKEYS')
#print(bytes.hex(publickey))
#publickey_2 = bytes.fromhex("039eff1f547a1d5f92dfa2ba7af6ac971a4bd03ba4a734b03156a256b8ad3a1ef9")
#print(pubkey_2)
#s = hashlib.new('sha256',    publickey).digest()
#r = hashlib.new('ripemd160', s        ).digest()
#teste = CScript([OP_0, r])

# print(bytes.hex(r))
# print(bytes.hex(txout_scriptPubKey))

# [117, 241, 76, 217, 45, 164, 167, 150, 197, 181, 179, 169, 107, 186, 243, 84, 215, 84, 164, 78, 161, 201, 172, 62, 223, 66, 156, 179, 144, 124, 84, 38] tp hex string

# subtype2 = [117, 241, 76, 217, 45, 164, 167, 150, 197, 181, 179, 169, 107, 186, 243, 84, 215, 84, 164, 78, 161, 201, 172, 62, 223, 66, 156, 179, 144, 124, 84, 38]
# hex_subtype2 = integer_array_to_hex_string_BE(subtype2)

# pprint(hex_subtype2)