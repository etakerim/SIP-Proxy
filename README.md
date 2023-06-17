# SIP Proxy 
Mobile Technologies and Applications (Summer semester 2021/22), Faculty of informatics and information technologies STU
in Bratislava. 

## Description

Simple telephone exchange to connect multiple standard SIP clients by message forwarding on different UDP ports 
(such as Linphone, Zoiper, etc.). It is written in Python3.8 above `sockerserver` package. 
It builds upon previous open source example of SIP proxy: https://github.com/tirfil/PySipFullProxy 

## Principals of telephone exchange

The UDP server listens on the standard SIP port 5060 (according to `SIP_PORT` in settings.py). The
requests are delegated to the `handle()` method in the `SIPProxy` class. According to the SIP protocol method used
(REGISTER, INVITE, BYE, etc.) it is then decided whether the message will be between clients only
forwarded in a largely unchanged state, or some SIPs will be overwritten along the way (headers), 
or the proxy will respond directly to the request.

## User manual
First it is necessary to manually edit in `settings.py`:
- Proxy IP address in the `SIP_IP` constant according to the active network interface.
- The file name in the `LOG_FILENAME` constant for the log of calls and SIP proxy operational messages. By default, they are saved in the file: `call.log`
- The SIP proxy is started by the command from the root directory of the project:

```bash
python main.py
```

## PCAP recodings
- 01-register.pcap: Participant registration
- 02-calling.pcap: Making a call and ringing on the other side
- 03-accept-call.pcap: Call acceptance by the other party and a working voice call
- 04-hangup.pcap: Ending received call
- 04-cancel-call.pcap: Call not accepted
- 04-decline-call.pcap: Decline a missed call
- whole-call.pcap: Recording of the entire voice call. Divided into files: 01-
register.pcap, 02-calling.pcap, 03-accept-call.pcap, 04-hangup.pcap
- conference.pcap: conference call
- transfer-call.pcap: call forwarding
- videocall.pcap: video call


