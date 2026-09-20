Disclaimer:
THIS IS MADE ONLY FOR EDUCATIONAL PURPOSES, DO NOT MISUSE.
(This script operates primarily at the Data Link Layer (Layer 2) and Physical Layer (Layer 1) of the OSI framework)
(Don't use VPN to do this, use sum dummy device, but it's not that serious cuz this script is undetectable, and it restores the packets upon exiting. But still the admin can see who connected to the wifi.)
(This is for windows, works in linux too, but using Wireshark is highly recommended.)
well well well nigga
so all you gotta do is, install npcap in your pc.
Run it, then download this zip file. Turn on ip forwarding in your pc (in the registry keys).
Make sure that the wifi has no AP isolation. To know this, Run devices.py, after connecting to the wifi.
If It gives you the ip of the devices conencted to the network, then you're in.
Forget the first 2 ip addresses, it's your device ip and your router's ip, you don't need them. Get the victim's ip.
after getting the victim's ip, run arp_spoof.py it'll ask for your ip, press enter if it shows your correct ip.  It'll show the correct gateway ip, which is correct, so press enter.
Now enter the victim's ip that you js copied. It'll start to spoof arp packets.
Here comes the monitor script, run sniffer.py it'll ask for the target ip, Press enter to scan every ip, or enter the victim's ip to concentrate on his device.
Now it'll show the domains the victim visits. Therefore, you can spy on what he's doing.
(irrelevant sites will get hid.)
