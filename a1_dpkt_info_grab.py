#!/usr/bin/env python3

#----- Imports -----
from __future__ import print_function
import dpkt
from dpkt.utils import mac_to_str, inet_to_str
import re
from termcolor import colored, cprint
from os.path import exists
from prettytable import PrettyTable
#-------------------


#-----------------------------------------------------------------------------------
#----- HTTPS NOT CURRENTLY SUPPORTED -----
#----- Initializing PCAP File -----
#fileName = 'Hancitor-Cobalt-Strike.pcap'
#fileName = 'qakbot-cobalt-strike.pcap'
#fileName = 'trickbot-cobalt-strike.pcap'
#fileName = 'squirrelwaffle-cobalt-strike.pcap'

def loadMessage(fileName):
    #print('Opening {}...'.format(fileName))
    print(colored('[!] Opening ' + fileName, 'green'))
    fileExists = exists(fileName)
    if fileExists:
        print(colored('[!] PCAP Successfully Loaded', 'green'))
    else:
        print(colored('[X] PCAP Not Found', 'red'))
        quit()

#loadMessage(fileName)

def processPcap(fileName):
    #----- Initializing Variables -----
    completeIPInfo = ''
    completeHostInfo = ''
    unfilteredIPSourceList = ''
    unfilteredIPDestList = ''
    completeURIInfo = ''
    completeLink = ''
    cobaltReconPresent = False
    suspiciousGETFiletype = False

    #----- Opened and Read PCAP -----
    file = open(fileName, "rb")
    pcap = dpkt.pcap.Reader(file)
    #----- Parse Packet Data Into Ethernet class -----
    for timeStamp, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        
        if not isinstance(eth.data, dpkt.ip.IP):
            #print("IP Packet Type Not Supported\n") # Annoying to have it print out so many times
            continue
        #----- Getting the data within the ethernet frame (the IP packet) -----
        ip = eth.data

        #----- Checking for TCP in the transport layer -----
        if isinstance(ip.data, dpkt.tcp.TCP):
            #----- Assign TCP data -----
            tcp = ip.data
            
            #print(tcp) # <---- make sure to comment this out, it'll dump a bunch of information
            #print(ip)
            #----- Parse contents of HTTP Request -----
            try:
                request = dpkt.http.Request(tcp.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            httpRequest = repr(request)
            #print(httpRequest + "\n\n") # for debugging

            #----- Add info to ip source list, ip dest list, and http contents list to be returned to main ----- 
            unfilteredIPSourceList = unfilteredIPSourceList + inet_to_str(ip.src) + "\n"
            unfilteredIPDestList = unfilteredIPDestList + inet_to_str(ip.dst) + "\n"
            #---------------------------------------------------------------------------------------------

            #----- Get HTTP Host Contents and Concat Them -----
            httpHostInfo = ''
            httpHostInfo = re.search("host', '(.+?)'", httpRequest)#.group(1) # Fancy Regex stuff being used
            if httpHostInfo:
                httpHostInfo = format(httpHostInfo.group(1))
                #completeHostInfo = ''
                completeHostInfo = completeHostInfo + httpHostInfo + "\n"
            else:
                None

            #----- Combine URI info w/ URL ----- idea for later?
            linkHostInfo = ''
            linkURIInfo = ''
            linkHostInfo = re.search("host', '(.+?)'", httpRequest)
            linkURIInfo = re.search("uri='(.+?)',", httpRequest)
            if linkHostInfo and linkURIInfo:
                linkHostInfo = format(linkHostInfo.group(1))
                linkURIInfo = format(linkURIInfo.group(1))
                completeLink = completeLink + linkHostInfo + linkURIInfo + "\n"
            else:
                None

            #----- Grab IP Mentioned in Packets -----
            IPInfo = ''
            IPInfo = re.search("IP=(.+?)&", httpRequest)#.group(1) # Fancy Regex stuff being used
            if IPInfo:
                IPInfo = format(IPInfo.group(1))
                #completeIPInfo = ''
                completeIPInfo = completeIPInfo + IPInfo + "\n"
            else:
                None

            #----- Grab GUID= and INFO= when looking for Cobalt strike info recon -----
            
            guidInfoPresent = ''
            infoInfoPresent = ''
            ipInfoPresent = ''
            nt61UserAgent = ''
            guidInfoPresent = re.search("GUID=(.+?)", httpRequest)
            infoInfoPresent = re.search("&INFO=(.+?)", httpRequest)
            ipInfoPresent = re.search("&IP=(.+?)", httpRequest)
            nt61UserAgent = re.search("Windows NT 6.1(.+?)", httpRequest)
            if guidInfoPresent or infoInfoPresent or ipInfoPresent:
                cobaltReconPresent = True
            else:
                None

            #----- Alerting to Suspicious file type GET request HTTP -----
            # filetypes like .gif, .ico,
            method = ''
            method = re.search("method='GET'", httpRequest)
            uriICOExtension = ''
            uriICOExtension = re.search("uri='(.+?).ico'", httpRequest)
            uriGIFExtension = ''
            uriGIFExtension = re.search("uri='(.+?).gif'", httpRequest)
            if method and (uriICOExtension or uriGIFExtension):
                suspiciousGETFiletype = True
            else:
                None

            #----- Find domain information being sent out -----
            # like domain/user kinda stuff
            
            #----- Checking for header spanning across TCP segments
            #if not tcp.data.endswith(b'\r\n'):
                #print("\nHeader has been truncated! Reassemble TCP segments!\n")

    #return unfilteredIPSoureList, unfilteredIPDestList, httpContents
    return unfilteredIPSourceList, unfilteredIPDestList, completeHostInfo, completeIPInfo, completeURIInfo, completeLink, cobaltReconPresent, suspiciousGETFiletype


#unfilteredIPSourceList, unfilteredIPDestList, completeHostInfo, completeIPInfo, completeURIInfo, completeLink, cobaltReconPresent, suspiciousGETFiletype = processPcap(fileName)

#for i in unfilteredIPSourceList:
#print(unfilteredIPSourceList + "\n") # Just handy to have
#print(unfilteredIPDestList + "\n") # Can use this to look for malicious IPs
#print(completeHostInfo + "\n") # Can use this to look for malicious sites
#print(completeIPInfo + "\n") # Grabbing more IPs from HTTP Header/Content areas
def removeDuplicates(sentList):
    needSort = sentList.split()
    result = []
    [result.append(x) for x in needSort if x not in result]

    return result

def addBlankstoList(list1, list2, list3, list4, list5):
    lengthList1 = len(list1)
    lengthList2 = len(list2)
    lengthList3 = len(list3)
    lengthList4 = len(list4)
    lengthList5 = len(list5)
    #need to use this to find number of rows needed for table

    numberOfRows = max(lengthList1, lengthList2, lengthList3, lengthList4, lengthList5)
    return numberOfRows
    
def removingDupes(unfilteredIPSourceList, unfilteredIPDestList, completeHostInfo, completeIPInfo, completeLink):
    sortedIPSourceList = removeDuplicates(unfilteredIPSourceList)
    sortedIPDestList = removeDuplicates(unfilteredIPDestList)
    sortedHostInfo = removeDuplicates(completeHostInfo)
    sortedIPInfo = removeDuplicates(completeIPInfo)
    #sortedURIInfo = removeDuplicates(completeURIInfo)
    #print(sortedURIInfo)
    sortedLink = removeDuplicates(completeLink)

    #insert blanks at end of list to get them to work with prettyTable
    numberOfRows = addBlankstoList(sortedIPSourceList, sortedIPDestList, sortedHostInfo, sortedIPInfo, sortedLink)

    return sortedIPSourceList, sortedIPDestList, sortedHostInfo, sortedIPInfo, sortedLink, numberOfRows

def printLists(listToPrint):
    #print(colored('[!] PCAP Successfully Loaded', 'green'))
    if listToPrint:
        print(colored('\n' + '----- Started -----', 'green'))
        for i in range(len(listToPrint)):
            print(colored(listToPrint[i], 'blue'))
        print(colored('----- Finished -----', 'green'))
    else:
        None

def addRowNumber(list, numberOfRows):
    # this is used to add dashes to list, PrettyTable did
    # not like columns that weren't the same size
    listLength1 = len(list)
    neededRows = numberOfRows - listLength1
    #print(numberOfRows)
    for i in range(neededRows):
        list.append('')

    return list
    
def printListsTable(sortedIPSourceList, sortedIPDestList, sortedHostInfo, sortedIPInfo, sortedLink, numberOfRows): # Print lists into a nice and pretty table
    #table = PrettyTable(['IP Source', 'IP Destination'])
    #table.add_row([sortedIPDestList, 24])
    table = PrettyTable([])

    sortedIPSourceList = addRowNumber(sortedIPSourceList, numberOfRows)
    table.add_column('IP Sources', sortedIPSourceList)
    
    sortedIPDestList = addRowNumber(sortedIPDestList, numberOfRows)
    table.add_column('IP Destinations', sortedIPDestList)

    sortedHostInfo = addRowNumber(sortedHostInfo, numberOfRows)
    table.add_column('Host Information', sortedHostInfo)

    sortedIPInfo = addRowNumber(sortedIPInfo, numberOfRows)
    table.add_column('IP Information', sortedIPInfo)

    sortedLink = addRowNumber(sortedLink, numberOfRows)
    table.add_column('Full Link Information', sortedLink)

    table.align = 'l'

    print(table)

#printLists(sortedIPSourceList)
#printLists(sortedIPDestList)
#printLists(sortedHostInfo)
#printLists(sortedIPInfo)
#printLists(sortedLink)

#if cobaltReconPresent == True:
    #print(colored("[WARNING] CobaltStrike Recon Present | INFO, GUID, IP being passed over HTTP | Potential IE User-Agent", 'red'))
#else:
    #None


# make this detect exe and dll as well
#if suspiciousGETFiletype == True:
    #print(colored("[WARNING] Suspicious GET Filetype Request | ico, gif", 'red'))
#else:
    #None

# Needed to make sure imports don't run straight away in main
if __name__ == '__main__':
    processPcap()

# Libraries to Check Out
# Scapy, PyShark

# Sources:
# https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html
# https://github.com/kbandla/dpkt/blob/master/examples/print_http_requests.py
# https://stackoverflow.com/questions/4666973/how-to-extract-the-substring-between-two-markers
# https://www.geeksforgeeks.org/python-ways-to-remove-duplicates-from-list/
# https://www.darkreading.com/threat-intelligence/how-to-identify-cobalt-strike-on-your-network