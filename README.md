# PingBanner
Respond to ICMP echo requests with a custom payload!

This program is designed to work as a custom ICMP echo reply server on Linux systems. It has been tested on Ubuntu Server 18.04 (and has surprisingly been running for nearly a year without any downtime! O_O )

This was mostly written at DEFCON 31 and finished up a few days later, so it's probably really jank and hacky.

## Setup
0) Edit the `ping_banner.py` file to change the message on line 124 to whatever you want
1) Get into a root shell (it's safe, trust me 😈)
2) Run `echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all` to turn off the OS's built-in ICMP echo reply mechanism
3) Run `python3 ping_banner.py` to start the custom ICMP echo reply server
4) Profit?

## Usage
If you ping the server, then the ICMP echo reply should contain the payload found in line 124 of the `ping_banner.py` file. This will be visible in [Wireshark](https://www.wireshark.org/) traces of the ICMP activity. On Mac computers, it seems like the built-in `ping` command will show that there's an error in the response, but if you look at the hex dump, then you'll see that it's the custom payload, but it was expecting a literal echo of whatever it sent to the server.
