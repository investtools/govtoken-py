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
# from bitcoin.core import b2x, b2lx, lx, COIN, COutPoint, CTxOut, CTxIn, CMutableTransaction
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

from generate_psbt import bip_obj_change

# get transaction generated by rgb
transaction_file = open('rgb_gen/transaction.tx', 'rb')
transaction = transaction_file.read()
transaction_dict = Psbt.parse(transaction).to_dict()

# A PARTIR DAQUI TEMOS QUE REVER:
# 1. PODEMOS CONTINUAR ASSIM E EXTRAIR A ASSINATURA DESSA TX NOVA E COLOCAR NA DO RBG
# 2. PODEMOS GERAR A ASSINATURA NÓS MESMOS E COLOCAR NA TX DO RGB

# extract relevant data from transaction
prev_out = transaction_dict['tx']['vin'][0]['prev_out']
input_amount = transaction_dict['inputs'][0]['witness_utxo']['value']
scriptPubKey_2 = CScript(bytes.fromhex(transaction_dict['inputs'][0]['witness_utxo']['scriptPubKey']))
pubkey_2 = transaction_dict['inputs'][0]['bip32_derivs'][0]['pub_key']
amount = transaction_dict['tx']['vout'][0]['value']
txid = prev_out['txid']
vout = prev_out['vout']
sighash_type = transaction_dict['inputs'][0]['sig_hash']
witness_program =  scriptPubKey_2.witness_program()

# generate transaction to be signed, from extracted data
txin = TxIn(bytes.fromhex(prev_out['txid']), 0, scriptPubKey_2, 0, witness_program=witness_program, value=int(float(input_amount)*10**8))
txout = TxOut((int(float(amount)*10**8)), script_pubkey=scriptPubKey_2)
tx_to_sign = Tx(version=2, tx_ins=[txin], tx_outs=[txout], locktime=0, testnet=True)

# get private key
priv_key = PrivateKey(int.from_bytes(bip_obj_change.PrivateKey().Raw().ToBytes(), "little"), compressed=True, testnet=True)

# sign transaction
was_signed = tx_to_sign.sign_input(0, priv_key, SIGHASH_ALL, compressed=True)

# get signature
sec = tx_to_sign.tx_ins[0].sec_pubkey(0)
der = tx_to_sign.tx_ins[0].der_signature(0)
z = tx_to_sign.sig_hash_bip143(0, der[1])
new_sig = z.to_bytes(len(str(z)), 'little')

# add signature to original transaction
psbt_to_sign = Signer(transaction)
psbt_to_sign.add_partial_signature(der, sec, 0)