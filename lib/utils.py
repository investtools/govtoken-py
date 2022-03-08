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
    # convert integer array to bytes
    # [2147483692, 2147483649, 2147483648, 0] -> b'\x80\x00\x00\x2c\x80\x00\x00\x01\x80\x00\x00\x00\x00\x00\x00\x00'
    path_bytes = integer_array_to_hex_string(path_int)

    # path_hex = "8000002C"
    return path_bytes