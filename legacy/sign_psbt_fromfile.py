import io
from lib.psbt import psbt, Signer, Input_Finalizer
from lib.bitcoin_lib import hash160
from lib.utils import *
from generate_psbt import bip_obj_change, txo_tx_hexa
from lib.bitcoin_lib import *
from pprintpp import pprint

SIGHASH_ALL = bytes.fromhex("01")

private = PrivateKey(bip_obj_change.PrivateKey().Raw().ToInt())
signed = private.sign(int(SIGHASH_ALL.hex(), 16))
print(signed.r, signed.s)  # r, s
print(bytes.hex(signed.der()))
signature = signed.der()


# function to get DER from ECDSA point




psbt_file = open('rgb_gen/transaction.tx', 'rb')
psbt_obj = psbt_file.read()
print("*************************** psbt sign_psbt_fromfile")
print(Signer(psbt_obj).b64_psbt())
pprint(bytes.hex(Signer(psbt_obj).psbt.maps["inputs"][0][b'\x01']))
signed = Signer(psbt_obj).add_partial_signature(signature + SIGHASH_ALL, bip_obj_change.AddressIndex(0).PublicKey().RawCompressed().ToBytes(), input_index=0)
signed.psbt._validity_checking()
finalized = Input_Finalizer(signed.psbt.serialize())

print(finalized.psbt.get_as_b64())

signed.make_file("transaction_signed.tx")

