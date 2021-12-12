#!/usr/bin/env python3
# BushFire PCAP Parser and OSINT Scraper
# https://vimeo.com/651752389

#----- Library Imports -----
from __future__ import print_function
import dpkt
from dpkt.utils import mac_to_str, inet_to_str
import re
from termcolor import colored, cprint
from os.path import exists
#---------------------------------------------------------------

#----- My Imports -----
from a1_dpkt_info_grab import *
from a2_selenium_check import *
#from a3_scapy_info_grab import *
from a4_greynoise_shodan import *
#---------------------------------------------------------------

#----- PCAP Filenames ----- # Ensure it is in the same directory as the script
fileName = 'Hancitor-Cobalt-Strike.pcap'
#fileName = 'qakbot-cobalt-strike.pcap'
#fileName = 'trickbot-cobalt-strike.pcap'
#fileName = 'squirrelwaffle-cobalt-strike.pcap'
#---------------------------------------------------------------

#----- Ensure PCAP is Valid -----
loadMessage(fileName)
#----- PCAP Validation Complete -----

#----- Getting Information Using DPKT -----
unfilteredIPSourceList, unfilteredIPDestList, completeHostInfo, completeIPInfo, completeURIInfo, completeLink, cobaltReconPresent, suspiciousGETFiletype = processPcap(fileName)
# Sorting DPKT Info
sortedIPSourceList, sortedIPDestList, sortedHostInfo, sortedIPInfo, sortedLink, numberOfRows = removingDupes(unfilteredIPSourceList, unfilteredIPDestList, completeHostInfo, completeIPInfo, completeLink)
#----- Finished Getting Information -----

#----- Print the Lists in a Pretty Table -----
print(colored("PCAP Data:", "blue"))
printListsTable(sortedIPSourceList, sortedIPDestList, sortedHostInfo, sortedIPInfo, sortedLink, numberOfRows)
print("\n")
#----- Finished! ----- This section of the code relating to DPKT a1 is done
#---------------------------------------------------------------
#---------------------------------------------------------------
#---------------------------------------------------------------

#----- Using a2 Selenium Check Here -----
#for i in range(len(sortedIPDestList)): # DO NOT USE - DEPRECATED FOR LOOP
    #print(sortedIPDestList[i])
    #tweetIOCIP(sortedIPDestList[i])
    #print("\n") # this for loop is deprecated, now uneeded as I implemented them within the Selenium import
    # in order to ensure that the browser window stays open


while("" in sortedIPDestList):
    sortedIPDestList.remove("")

while("" in sortedHostInfo):
    sortedHostInfo.remove("")

#----- THESE ARE WORKING -----
print(colored("TweetIOC Data:", "blue"))
tweetIOCIP(sortedIPDestList)
tweetIOCURL(sortedHostInfo)
#-----------------------------
#----- These are working too -----

print(colored("AlienVault Data:", "blue"))
alienVaultIPCheck(sortedIPDestList)
#----------------------------------
#----------------------------------
#----------------------------------

#----- A4 import functions -----
print(colored("GreyNoise Data:", "blue"))
for i in range(len(sortedIPDestList)):
    greyOutput = greyNoiseIPCheck(sortedIPDestList[i])
    print(greyOutput)




