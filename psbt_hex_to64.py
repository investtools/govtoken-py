from lib.psbt import psbt, Signer

psbt_file = open('rgb_gen/transaction.tx', 'rb')
psbt_obj = psbt_file.read()
print(Signer(psbt_obj).b64_psbt())