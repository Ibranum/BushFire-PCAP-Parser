#----- Imports -----
from greynoise import GreyNoise
import re
import shodan


#-------------------

#----- API KEYS ENSURE YOU CLEANSE THESE -----



#----- Move API keys over to .txt file and load them in from there

#def virusTotalHashCheck(filehash):
    #None

#def virusTotalIPCheck(ipToCheck):
    #None

#def virusTotalURLCheck(urlToCheck):
    #None

#----- GreyNoise Section -----
def greyNoiseIPCheck(ipTargetAddress):
    greyNoiseAPIKey = ''
    greySession = GreyNoise(api_key=greyNoiseAPIKey, integration_name="sdk-sample")
    #ipTargetAddress = '197.44.154.90'
    greyOutput = []
    returnInfo = ''

    quickResponse = greySession.quick(ipTargetAddress)
    #print(quickResponse)

    for greyResult in quickResponse:
        if greyResult['noise']:
            context_response = greySession.ip(ipTargetAddress)
            context_response['noise'] = greyResult['noise']
            context_response['code'] = greyResult['code']
            context_response['code_message'] = greyResult['code_message']
            context_response['visualizer_url'] = 'https://viz.greynoise.io/ip' + str(ipTargetAddress)
            greyOutput.append(context_response)
        else:
            greyOutput.append(greyResult)

    
    #print(greyOutput) #testing and debugging
    #print("\n\n\n") #for testing and debugging

    greyString = ' '.join([str(elem) for elem in greyOutput]) #making it into a string to scan it

    #----- Using Regex to look for items in the results from GreyNoise -----
    noiseCheck = re.search("'noise': Tr(.+?),", greyString)
    riotCheck = re.search("'riot': True", greyString)
    scanCheck = re.search("IP has been observed", greyString)
    firstSeen = re.search("'first_seen': '(.+?)'", greyString)
    lastSeen = re.search("'last_seen': '(.+?)'", greyString)
    tags = re.search("'tags': (.+?)]", greyString)
    cve = re.search("'cve': (.+?)],", greyString)
    rdns = re.search("'rdns': '(.+?)'", greyString)
    
    #print(tags)
    #print(cve)
    #print(firstSeen)
    
    returnInfo = ipTargetAddress + "\n"
    
    if noiseCheck: # is true
        returnInfo = returnInfo + "Noise = True\n" 
    else:
        None

    if riotCheck:
        returnInfo = returnInfo + "Riot = True\n" 
    else:
        None

    if scanCheck:
        returnInfo = returnInfo + "IP has been observed scanning the internet\n" 
    else:
        None

    if firstSeen:
        firstSeen = format(firstSeen.group(1))
        returnInfo = returnInfo + "First Seen = " + firstSeen + "\n"
    else: 
        None

    if lastSeen:
        lastSeen = format(lastSeen.group(1))
        returnInfo = returnInfo + "Last Seen = " + lastSeen + "\n"
    else: 
        None

    if tags:
        tags = format(tags.group(1))
        tags = tags.replace("['", '')
        tags = tags.replace("'", '')
        returnInfo = returnInfo + tags + "\n"
    else: 
        None

    if cve:
        cve = format(cve.group(1))
        cve = cve.replace("['", '')
        cve = cve.replace("'", '')
        returnInfo = returnInfo + "CVE = " + cve + "\n"
    else: 
        None

    if rdns:
        rdns = format(rdns.group(1))
        returnInfo = returnInfo + "RDNS = " + rdns + "\n"
    else: 
        None

    #print(returnInfo)
    #print(noiseCheck)
    
    return returnInfo

#output = greyNoiseIPCheck()
#print(output)

def shodanIPCheck():
    shodanAPIKey = ''
    ipTargetAddress = '13.86.63.164'
    returnInfo = ''

    api = shodan.Shodan(shodanAPIKey)
    host = api.host(ipTargetAddress)

    print("""
        IP: {}
        Organization: {}
        Operating System: {}
    """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

    print("\n\n\n")

    #for item in host['data']:
        #print("""
                #Port: {}
                #Banner: {}

        #""".format(item['port'], item['data']))


    #----- Objectives for this function -----
    # We want to grab IP, Organization, Open Ports, City, Country, ASN, ISP, and name of service running on
    # the currently open ports, like Nginx

    
#shodanIPCheck()


# maybe utilize both vt library and official virustotal library? Do I need both?


if __name__ == '__main__':
    greyNoiseIPCheck()

