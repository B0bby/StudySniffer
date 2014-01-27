##StudySniffer
***

The goal of this project is to sniff for active wireless clients in common 'study' locations on campus to determine their relative level of activity, then display this data in the form of a heat-map in order to allow students to make a slightly more informed decision about where they want to study.

These are the scripts for setting up and controlling the hardware side of the project -- a raspberry pi with two wifi dongles.

The 'sniffing' aspect of the script is based on code from [this](http://pen-testing.sans.org/blog/2011/10/13/special-request-wireless-client-sniffing-with-scapy/comment-page-1/) article.

---

#### Dependencies
* scapy 2.2.0
* python 2.X
* python 3.X ( Yes, both. )

#### Setup
* Make sure you have two wireless interfaces
* Cross fingers
* Run setup.py

#### Todo
* Setup should parse config file for missing parameters
* Setup should check if network connection is wired
* Setup should create cron job for updating
* Setup should set up daemon for sniffer

---

#### Notes
Pretty sloppy at the moment. I've only ever run it on cloned Raspberry Pis, but If for some reason you're interested in setting something like this up, I'll try to offer a few suggestions as to why it's probably severely malfunctioning when you try to use it.

For one, it is a horrifying, two-faced monstrosity; a chimeran application -- half written in python3 and half in python2. You'll need both in order to control this beast. Running the 'setup.py' script in python3 should be enough, though, as the script *itself* then launches the *actual* script in python2 using subprocess.

There are more reasons, but for some reason they escape me.
