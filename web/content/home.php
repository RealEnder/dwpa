<h1>Online WPA cracker with stats - besside-ng companion</h1>
Contribute to WPA security research - the more handshakes you upload, the more
stats, and the more we'll understand how feasible WPA cracking is in practice.

<p>
<h4>Usage</h4>
To obtain the WPA handshake, use besside-ng (from <a href="http://www.aircrack-ng.org/downloads.html">aircrack-ng</a>'s SVN), a tool that will automatically own all the WPA networks it finds. If you have Internet connectivity while running besside-ng, use the -s wpa.darkircop.org option to upload wpa.cap automatically.
</p>

<p>
<h4>Distributed WPA cracking</h4>
Contribute your CPU to the cracking process by running <a href="hc/help_crack.py">help_crack.py</a>, a script that will automatically fetch uncracked networks, try to crack them, and upload the results to this site. If you want to use your own wordlist, pass it as an argument. Prerequisite: you must have python(tested with 2.7) pyrit or aircrack-ng installed. Default on posix platform is to use pyrit for cracking due to better performance and scalability.
</p>
<p>
<h4>Cracking under Windows</h4>
Install python 2.x from <a href="http://python.org/download/">here</a>. Then download precompiled binary of aircrack-ng - local version, with only commandline aircrack-ng inside <a href="hc/aircrack-ng-stripped-1.1-win.zip">here</a> or full distribution <a href="http://www.aircrack-ng.org/downloads.html">here</a>. Put aircrack-ng executables and <a href="hc/help_crack.py">help_crack.py</a> in same directory and run help_crack.py from cmd shell.
</p>
