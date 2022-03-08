#include <vector>
#include <iostream>

// This function from https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L110,
// MIT Licence. (c) 2009-2015 Satoshi Nakamoto and the Bitcoin Core developers
bool static IsValidSignatureEncoding(const std::vector<unsigned char> &sig) {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (sig.size() < 9) return false;
    if (sig.size() > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != sig.size() - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= sig.size()) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != sig.size()) return false;
 
    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

int main()
{
	unsigned char buf[] = {
		0x30, 0x44, 0x02, 0x20, 0x2A, 0xEE, 0xF9, 0x93, 0x03, 0x5E, 0x52, 0xB5, 0x42, 0x2C, 0x97, 0xB0,
		0x6A, 0xCB, 0x06, 0x25, 0xE5, 0x84, 0xCC, 0xF0, 0xA4, 0x81, 0xF6, 0x6F, 0x91, 0x16, 0xD3, 0xE7,
		0xBB, 0xD1, 0x0A, 0x08, 0x02, 0x20, 0x46, 0xA2, 0x8D, 0x43, 0x66, 0x7C, 0xF6, 0xF9, 0x36, 0x7B,
		0x21, 0x2D, 0x47, 0x55, 0xD7, 0x2F, 0x50, 0x5C, 0xA1, 0x41, 0xC5, 0x9B, 0x00, 0x46, 0x78, 0x7E,
		0xEE, 0x89, 0x83, 0x63, 0xEF, 0x23, 0x01
	};
	
	std::vector<unsigned char> yourSig;
	yourSig.assign(buf, buf + sizeof(buf));
	
	if(IsValidSignatureEncoding(yourSig))
		std::cout << "Your signature is perfectly fine!" << std::endl;
	else
		std::cout << "Yikes! Something fishy is going on!" << std::endl;
	
	return 0;
}

