# PUSH
Packetizer for Unix Shell Hosts

Applications
============

1. Generate and send packet frame.
2. Send frames stored as hex streams from file.
3. Send frames from pcap capture file.
4. Adjust sending rate.
5. Capture packets with pcap filter support.

Dependancies
============

pcap library should be installed.
dialog application should be installed.


Compilation
===========

sh build.sh

Usage
=====
push -bh -i <interface-name> -n <number-of-packets-to-capture>
     -f <capture-filter> -x <hex-stream-file-name> -r <frame-rate>
     -p <pcap-file-name> -c <capture-file>
     -d <optional-debug-args>

OPTIONS:
     -i, --interface      : Interface on which send/recv to be done.
                            Args required: interface name
     -c, --capture        : Enable capture, output pcap file will be
                            generated: "capture.pcap".
                            Optional Args required: capture file name.
     -n, --numCapture     : Number of packets to capture.
                            Args required: packet count
     -f, --filter         : Capture filter. Capture filters can be found
                            here:"https://www.tcpdump.org/manpages/pcap-filter.7.html"
                            Args required: filter name
     -r, --framerate      : Frame rate in fps to send traffic.
                            Will not be accurate if debug enabled.
                            Args required: frame rate in fps
     -x, --hexstream      : Send packets from file. Packet should be
                            written in hex stream in this text file.
                            Args required: file name
     -p, --pcapfile       : Send packets from pcap file.
                            Args required: pcap file name
     -b, --buildstream    : Generate packet stream and send.
     -d, --debug          : Enable debug options.
     -h, --help           : Help. Displays usage.
