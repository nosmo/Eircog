#!/usr/bin/python

import hashlib
import optparse
import os
import re
import subprocess
import sys
import time

from upc import UPC_REGEX, gen_upc_keys
import eircom

"""Default wifi key autogenerator for Mac OS X and Linux iwtools.

Eircom key generation entirely based upon the work of Kevin Devine. See upc.py for more details.
UPC key generation entirely based upon the work of bl4sty. See upc.py for more details.

Looking at this code 5 years later really nails home how much a giant
piece of shit it is. Rewrites coming.

"""

__author__ = "nosmo@netsoc.tcd.ie (nosmo)"

intwords = ["Zero","One","Two","Three","Four","Five","Six","Seven","Eight","Nine"]
inttoword = lambda a: intwords[int(a)]
hendrix = ["Although your world wonders me, ",
           "with your superior cackling hen,",
           "Your people I do not understand,",
           "So to you I shall put an end and"]

SLEEPINTERVAL = 5



def get_aps(numkeys, ssid=None, do_upc=False):
    """Scan and return interesting SSIDs, defaulting to Eircom

    Args:
     ssid: an optional supplied ssid for getting the key from the command line
     do_upc: whether to harvest UPC keys

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

            #len(ssid[0]) is to stop detection of "eircom" SSIDs while still being lazy and not using re
            # TODO fix this whole section, this splitting stuff is absolute bullshit
            if line[0].startswith("eircom"):
                line[0] = line[0].strip("eircom")
                if re.compile("\d{4}").match(line[1]):
                    results.append([line[0], line[1]])
                else:
                    # Some people seem to be in the odd habit of joining the numbers
                    results.append([line[0]])
            elif line[0].startswith("UPC") and len(line[0]) == 10:
                if do_upc:
                    results.append([line[0]])

            else:
                try:
                    manufacheck = eircom.check_manufacturer(line[2])
                    if manufacheck:
                        print "!:"
                        macserial = serial_from_mac(line[2], manufacheck)
                        eircom.gen_eircom_keys(macserial, [line[0], line[1]], numkeys)
                        continue
                except Exception as e:
                    print("Hit exception {} while checking for {}".format(str(e), line))
                    continue

    elif sys.platform == "linux2":

        try:
            scanproc = subprocess.Popen(("/sbin/iwlist %s scanning" % optparse.options.interface),
                                    shell = True, stdout = subprocess.PIPE)
        except OSError:
            sys.stderr.write(("Couldn't find iwlist - is it installed?\n If so, you might need "
                             "to change the path inside the script\n"))
            sys.exit(1)
        output = scanproc.communicate()[0].split("\n")

        for line in output:
            if line.find("ESSID:") != -1:
                ssid = line.split("\"")[1]
                ssid = ssid.split(" ")
                if ssid[0].startswith("eircom") and len(ssid[0]) >= 6:
                    ssid[0] = ssid[0].strip("eircom")
                    results.append(ssid)
                elif ssid[0].startswith("UPC"):
                    results.append(ssid)

    elif sys.platform == "ssidonly":

        single = []

        for i in ssid.split(" "):
            #TODO UPC support
            if i.startswith("eircom") and len(ssid[0]) >= 6:
                i = i.strip("eircom")
            single.append(i)
        results.append(single)

    return results



def do_all(numkeys, do_upc):
    """Do everything, really.

     Call all of the relevant functions in order to get the serial key, then
    do the SHA-related hackery to get the actual key(s).

    Args:
      numkeys: the number of keys to generate - 1 or 4.
      do_upc: whether or not to generate keys for UPC{d}\7 APs

    Returns:
      None
    """

    print "Scan in progress"
    access_points = get_aps(numkeys, optparse.options.ssidonly, do_upc=do_upc)
    print("Got {} APs".format(len(access_points)))

    octalbits = []
    upc_list = []

    for ap in access_points:
        if do_upc and ap[0].startswith("UPC"):
            upc_match = UPC_REGEX.match(ap[0])
            if upc_match:
                upc_digits = int(upc_match.groups()[0])
                upc_list.append(upc_digits)

        else:
            octconv = []
            for chunk in ap:
                if chunk.startswith("eircom"):
                    chunk = chunk[6:]
                octconv.append(int(chunk, 8))

            octalbits.append(octconv)
            serial = serial_number(octconv)

            keymass = ""

            gen_eircom_keys(serial, ap, numkeys)

    if upc_list:
        print "Generating UPC keys, please wait..."
        upc_results = gen_upc_keys(*upc_list)

    for upc_int in upc_list:
        print "UPC%d" % upc_int
        potential_phrases = upc_results[upc_int]
        for potential_phrase in potential_phrases:
            print "\t- %s" % potential_phrase

def main():
    #TODO  replace optparse with argparse
    parser = optparse.OptionParser(usage=("Usage: Eircog.py [-s|--ssidonly "
                                          "ssidstring] [-d] [-4] [-i INTERFACE] [-U]"))

    parser.add_option("-s", "--ssidonly", action="store", type="string",
                     dest="ssidonly", help=("Specifies a manual SSID, no scanning "
                                            "is done (Don't forget double quotes for"
                                            " spaces!"))
    parser.add_option("-i", "--interface", action="store", type="string",
                     dest="interface", help="The interface to scan with.")

    parser.add_option("-C", "--continuous", action="store_true", default=False,
                      dest="continuous", help="Scan and generate keys constantly.")
    parser.add_option("-U", "--upc", action="store_true", default=False,
                      dest="do_upc",
                      help="Generate suggestions for UPC SSIDs. Takes time.")
    parser.add_option("-4", action="store_true", default=False, dest="allkeys",
                      help="Generate all four keys instead of just one.")
    parser.add_option("--force-upc", action="store_true", default=False, dest="force_upc",
                      help="Force UPC key generation.")

    (optparse.options, optparse.args) = parser.parse_args()

    if optparse.options.ssidonly:
        #TODO this is really stupid, don't do this what the absolute fuck
        sys.platform = "ssidonly"

    numkeys = 1

    if optparse.options.allkeys:
        numkeys = 4
    if sys.platform == "linux" and not(optparse.options.interface):
        sys.stderr.write("Interface not specified!\n")
        sys.exit(1)

    if optparse.options.continuous:
        if optparse.options.do_upc and not optparse.option.force_upc:
            sys.stderr.write(("UPC keys take so long to generate that there's no"
                              " point combining it with continuous mode. If you "
                              "*really* want to do this, use the "
                              "--force-upc argument."))
            sys.exit(1)
        os.system("/usr/bin/clear")
        while True:
            os.system("/usr/bin/clear")
            do_all(numkey, optparse.options.do_upc)
            time.sleep(SLEEPINTERVAL)

    else:
        do_all(numkeys, optparse.options.do_upc)


if __name__ == "__main__":
    main()
