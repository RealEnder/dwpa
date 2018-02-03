<h1>Introduction</h1>
This is a community effort to study and improve security of WPA protected WiFi networks.
You can contribute to WPA security research - the more handshakes you upload, the more
stats, and the more we'll understand how feasible WPA cracking is in practice.<br/>
Source code is available at <a href="https://github.com/RealEnder/dwpa">GitHub</a>.

<p>
<h4>Usage</h4>
First step is to <a href="?get_key">issue your own key</a>. This is nessesary if you want to see the results from your uploaded handshakes.
To obtain the WPA handshake, use hcxdumptool or wlandump-ng from <a href="https://github.com/ZerBea/hcxtools">hcxtools</a> repo.
hcxtools is new generation sophisticated set of tools for WPA audit and penetration tests.
You can then <a href="?submit">upload</a> valid pcap format captures via the web interface.<br/>
Note: please do not use any additional tools to strip or modify the capture files, since they can mangle handshakes and lead to uncrackable results.
</p>

<p>
<h4>Distributed WPA cracking</h4>
There is no dedicated resource on this machine for handshake cracking.
All the work is done from volunteers like you, who contribute CPU/GPU
to the cracking process by running <a href="hc/help_crack.py">help_crack.py</a> [<a href="hc/CHANGELOG">CHANGELOG</a>],
a script that will automatically fetch uncracked handshake, download wordlist, try to crack, and upload the results to this site.
Prerequisite: you must have python 2.7 and <a href="https://hashcat.net/hashcat/">Hashcat</a> installed.
</p>

<p>
<h4>Cracking under Windows</h4>
Install Python 2.7 from <a href="https://python.org/download/">here</a> and
Python for Windows extensions from <a href="http://sourceforge.net/projects/pywin32/files/pywin32">here</a>.<br/>
Put executables and <a href="hc/help_crack.py">help_crack.py</a> in same directory and run help_crack.py from cmd shell.
</p>
