<h1>Introduction</h1>
<p>
This is a community effort to study and improve security of WPA protected WiFi networks.
You can contribute to WPA security research - the more captures you upload, the more
stats, and the more we'll understand how feasible WPA cracking is in practice.<br>
Source code is available at <a href="https://github.com/RealEnder/dwpa">GitHub</a>.
</p>
<h4>Usage</h4>
<p>
First step is to <a href="?get_key">issue your own key</a>. This is nessesary if you want to see the results from your uploads.
To obtain the WPA handshake or PMKID, use <a href="https://github.com/ZerBea/hcxdumptool">hcxdumptool</a>.
<a href="https://github.com/ZerBea/hcxtools">hcxtools</a> is new generation sophisticated set of tools for WPA audit and penetration tests.
You can then <a href="?submit">upload</a> valid pcap format captures via the web interface.<br>
Note: please do not use any additional tools to strip or modify the capture files, since they can mangle handshakes and lead to uncrackable results.
</p>

<h4>Distributed WPA cracking</h4>
<p>
There is no dedicated resource on this machine for cracking.
All the work is done from volunteers like you, who contribute CPU/GPU
to the cracking process by running <a href="hc/help_crack.py">help_crack.py</a> [<a href="hc/CHANGELOG">CHANGELOG</a>],
a script that will automatically fetch uncracked hashes, download wordlist, try to crack, and upload the results to this site.
Prerequisite: you must have python and <a href="https://hashcat.net/hashcat/">hashcat</a> or <a href="https://github.com/openwall/john">John the Ripper</a> "bleeding-jumbo" branch installed.<br>
Put help_crack.py in the same directory as cracker binary and run it from there.
</p>

<h4>Cracking under Windows</h4>
<p>
Install Python from <a href="https://python.org/download/">here</a>.
Put cracker executables and <a href="hc/help_crack.py">help_crack.py</a> in the same directory and run help_crack.py from cmd shell.
</p>
