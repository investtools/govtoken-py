import linecache
from hashlib import sha256


class Mnemonic:
    def __init__(self, input_string):
        input_hex = sha256(input_string.encode('utf-8')).hexdigest()
        int_string = int(input_hex, 16)
        cut, cursor, n_words = 0b11111111111, 0, 23
        self.words = ""
        for i in range (n_words):
            line_n = (int_string >> cursor) & cut
            self.words += linecache.getline('assets/wordlist.txt', line_n).rstrip("\n")
            self.words += " "
            cursor += 11

        line_n = int.from_bytes(sha256(bytes.fromhex(input_hex)).digest(), 'little') & 0b11111111
        self.words+=linecache.getline('assets/wordlist.txt', line_n).rstrip("\n")   
        
    def get_mnemonic(self):
        return self.words