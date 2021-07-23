Eircog
=======


Introduction
-------

Eircog is a Python tool that is used to actively generate keys for
nearby access points that are vulnerable to

* the Netopia predictable WEP key generation issue discovered by Kevin
 Devine, most commonly found in the routers of a particularly large
 Irish telco.

* [bl4sty](https://twitter.com/bl4sty)'s WPA key generation method for UPC
  routers in various countries.

It uses system binaries to obtain the SSIDs of nearby access points
under Linux and OS X and then generates the corresponding keys.

This tool requires iwtools under Linux (and permission to run iwlist).

This tool was not built with malice in mind but frankly has little honourable application.

Command-line arguments:
-------

```--help```: show help information

```--s=SSIDSTRING``` or ```--ssidonly=SSIDSTRING```: return the key(s) for a given string and immediately exit.

```--interface=INTERFACE``` or ```-i=INTERFACE```: Specify the interface to scan with. This is MANDATORY in Linux. Has no effect under OS X.

```-d``` or ```--daemon```: Run the script constantly, scanning every SLEEPINTERVAL (by default this is 5 seconds). The term "daemon" is used because I was a moron. To be fixed.

```-4```: Generate 4 keys instead of the standard 1 when using the Eircom exploit.

```-U```: Generate UPC key suggestions - this will VASTLY increase execution time.

TODO
------

Add an option for key injection without joining, to save the user copy and pasting and to
allow one scan of an area to potentially provide access to all seen APs. This might be doable
with OS X's `security` command, although it doesn't seem to give access to the part of the
keychain that looks after "Airport" entries. I'm not sure about how this storage could be
done in Linux, assumedly files for Network Manager or equivalent commands could be altered.

Addendum
-------

A disclaimer as regards the use of this script goes here but that would be insulting to the intelligence of the reader
