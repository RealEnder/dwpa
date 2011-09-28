<h1>Introduction</h1>
This is a community effort to study and improve security of WPA protected WiFi networks.
You can contribute to WPA security research - the more handshakes you upload, the more
stats, and the more we'll understand how feasible WPA cracking is in practice.<br/>
This site is based on sorbo's work on <a href="http://wpa.darkircop.org">wpa.darkircop.org</a>.

<p>
<h4>Usage</h4>
First step is to <a href="?get_key">issue your own key</a>. This is nessesary if you want to see the results from your uploaded handshakes.
To obtain the WPA handshake, use besside-ng (from <a href="http://www.aircrack-ng.org/downloads.html">aircrack-ng</a>'s SVN), a tool that will automatically collect and store handshakes for all the WPA networks it finds. If you have Internet connectivity while running besside-ng, use the -s wpa-sec.stanev.org option to upload wpa.cap automatically. However, this will not associate your key with the handshakes.
</p>

<p>
<h4>Distributed WPA cracking</h4>
There is no dedicated resource on this machine for handshake cracking. All the work is done from volunteers like you, who contribute CPU/GPU to the cracking process by running <a href="hc/help_crack.py">help_crack.py</a>, a script that will automatically fetch uncracked network, download wordlist, try to crack, and upload the results to this site. If you want to use your own wordlist, pass it as an argument. Prerequisite: you must have python(tested with 2.7) pyrit or aircrack-ng installed. Default on posix platform is to use pyrit for cracking due to better performance and scalability.
</p>

<p>
<h4>Cracking under Windows</h4>
Install python 2.x from <a href="http://python.org/download/">here</a>. Then download precompiled binary of aircrack-ng - local version, with only commandline aircrack-ng with oclHashcat-plus support inside <a href="hc/aircrack-ng-stripped-1.1r1975-win.zip">here</a> or full distribution <a href="http://www.aircrack-ng.org/downloads.html">here</a>. Put aircrack-ng executables and <a href="hc/help_crack.py">help_crack.py</a> in same directory and run help_crack.py from cmd shell.
</p>
