# this file is not used in the turned in program. It is here for later purposes only

#----- Imports -----
from scapy.all import *
#-------------------

#----- PCAPs for Testing -----------------------
fileName = 'Hancitor-Cobalt-Strike.pcap'
#fileName = 'qakbot-cobalt-strike.pcap'
#fileName = 'trickbot-cobalt-strike.pcap'
#fileName = 'squirrelwaffle-cobalt-strike.pcap'
#-----------------------------------------------


pcapData = rdpcap(fileName)
sessions = pcapData.sessions()

for session in sessions:
    filePayload = ''
    for packet in sessions[session]:
        try:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                #print(packet[TCP].payload)
                None
        except:
            pass







