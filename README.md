# ~$ Honeypot
Simple honeypot writen in python with scapy.

* Proof: https://www.youtube.com/watch?v=QFwL5EOFNCQ
* Writeup: https://csi-blog.com/honeypot/


# ~$ Description
The script will detect your mac address (manual sellection coming soon),

and will sniff all incoming TCP data for all 65535 ports,

and will respond as Syn/Ack on all ports.


# ~$ Usage
$ python honeypot.py
