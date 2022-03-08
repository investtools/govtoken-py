from lib.psbt import psbt

stdin = input().strip()
psbt_obj = psbt.parse_b64(stdin)
# export psbt
newFile = open("psbt_rust.hex", "wb")
newFileByteArray = bytearray(psbt_obj.serialize())
is_written = newFile.write(newFileByteArray)
print("Written:", is_written)