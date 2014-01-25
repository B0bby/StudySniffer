##StudySniffer
***
#### Dependencies
* scapy 2.2.0
* python 2.7.4 +

#### Setup
* Put desired wireless interface into monitor mode
	* iw dev [interface] interface add mon0 type monitor
	* ip link set mon0 up
* Run StudyspotSniffer.py

#### TODO
* Add queueing function in case server is unreachable
* Implement ability to update files based on git changes
