#----- Imports -----
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options
import time
import warnings
from sys import platform
import os
from termcolor import colored, cprint
#-------------------

# make the warnings be quiet
def suppressWarnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)

#url = 'forkineler.com/8/forum.php'
#ip = '13.107.4.50'

def tweetIOCURL(url):
    #----- Initialize Selenium -----
    if platform == "win32":
        #print(colored("[i] Windows OS Detected", 'blue'))
        gecko = (r"C:/Users/Evan/iCloudDrive/iCloud~md~obsidian/Evan's Apple Vault/Fall 2021 Semester/INFA-713 Managing Security Risks/Semester Project/Python Project 1/firefox-geckodrivers/Windows/geckodriver.exe")
        options = Options()
        options.headless = True
        #binary = FirefoxBinary(r'/Applications/Firefox.app')
        #driver = webdriver.Firefox(options=options, executable_path=gecko) #headless running
        driver = webdriver.Firefox(executable_path=gecko)
    else:
        #print(colored("[i] MacOS Detected", 'blue'))
        #print(colored('\n' + '----- Started -----', 'green'))
        gecko = (r"/Users/evan/Library/Mobile Documents/iCloud~md~obsidian/Documents/Evan's Apple Vault/Fall 2021 Semester/INFA-713 Managing Security Risks/Semester Project/Python Project 1/firefox-geckodrivers/Mac/geckodriver")
        #binary = FirefoxBinary(r'/Applications/Firefox.app')
        driver = webdriver.Firefox(executable_path=gecko)


    for i in range(len(url)):
        print(url[i])
        #----- Initialize Values -----
        IOCURLtableEntryPresent = False
        tweetIOCURLData = ""

        #----- Use Selenium to Check Tweetioc.com for URL -----
        driver.get("http://tweettioc.com/search")
        #time.sleep(3)

        #list = driver.find_elements_by_id('query') # tested, two query id are present on search page
        #print(list)

        #----- Choose the URL Options from Dropdown Menu
        dropDown = driver.find_elements_by_id('type')[1]
        dropDown.click()
        select = Select(driver.find_elements_by_id('type')[1])
        select.select_by_value('url')

        #----- Enter into search bar -----
        searchBox = driver.find_elements_by_id('query')[1]
        searchBox.click()
        searchBox.send_keys(url[i], Keys.ENTER)
        time.sleep(1)

        #----- Check if info in table is present -----
        try:
            driver.find_element_by_xpath('/html/body/div[1]/div[2]/div[2]/div/div/div[2]/div/div[2]/div/div/table/tbody/tr/td[1]')
            IOCURLtableEntryPresent = True
        except:
            None
        #rows = 1 + len(driver.find_elements_by_xpath("/html/body/div[1]/div[2]/div[2]/div/div/div[2]/div/div[2]/div/div/table/tbody/tr"))
        #columns = len(driver.find_elements_by_xpath("/html/body/div[1]/div[2]/div[2]/div/div/div[2]/div/div[2]/div/div/table/tbody/tr/td"))

        #print(rows + " " + columns)

        try:
            tweetIOCURLData = driver.find_element_by_xpath("/html/body/div[1]/div[2]/div[2]/div/div/div[2]/div/div[2]/div/div/table/tbody/tr/td[3]").text
            print(colored(tweetIOCURLData, "green"))
        except:
            print(colored("[x] No table data for TweetIOC URL Info", "red"))
        print("\n")
    
    urlOfPage = driver.current_url # Get current url of web page for later
    print(urlOfPage)
    print("\n")

    #----- Shut it down -----
    driver.close()

    #----- Return Values -----
    return IOCURLtableEntryPresent, tweetIOCURLData

#IOCURLtableEntryPresent, tweetIOCURLData = tweetIOCURL(url)
#print(IOCURLtableEntryPresent)
#print("\n\n\n")
#print(colored(tweetIOCURLData, "green"))

def tweetIOCIP(ip):
    #----- Initialize Selenium -----
    
    if platform == "win32":
        #print(colored("[i] Windows OS Detected", 'blue'))
        gecko = (r"C:/Users/Evan/iCloudDrive/iCloud~md~obsidian/Evan's Apple Vault/Fall 2021 Semester/INFA-713 Managing Security Risks/Semester Project/Python Project 1/firefox-geckodrivers/Windows/geckodriver.exe")
        options = Options()
        options.headless = True
        #binary = FirefoxBinary(r'/Applications/Firefox.app')
        #driver = webdriver.Firefox(options=options, executable_path=gecko) #headless running
        driver = webdriver.Firefox(executable_path=gecko)
    else:
        #print(colored("[i] MacOS Detected", 'blue'))
        #print(colored('\n' + '----- Started -----', 'green'))
        gecko = (r"/Users/evan/Library/Mobile Documents/iCloud~md~obsidian/Documents/Evan's Apple Vault/Fall 2021 Semester/INFA-713 Managing Security Risks/Semester Project/Python Project 1/firefox-geckodrivers/Mac/geckodriver")
        options = Options()
        options.headless = True
        #binary = FirefoxBinary(r'/Applications/Firefox.app')
        #driver = webdriver.Firefox(options=options, executable_path=gecko) #headless running
        driver = webdriver.Firefox(executable_path=gecko)
        
        

    for i in range(len(ip)):
        print(ip[i])
        
        #----- Initialize Values -----
        IOCIPtableEntryPresent = False
        tweetIOCIPData = ""

        #----- Use Selenium to Check Tweetioc.com for URL -----
        
        driver.get("http://tweettioc.com/search")
        #time.sleep(3)

        #list = driver.find_elements_by_id('query') # tested, two query id are present on search page
        #print(list)

        #----- Choose the URL Options from Dropdown Menu
        dropDown = driver.find_elements_by_id('type')[1]
        dropDown.click()
        select = Select(driver.find_elements_by_id('type')[1])
        select.select_by_value('ip')

        #----- Enter into search bar -----
        searchBox = driver.find_elements_by_id('query')[1]
        searchBox.click()
        searchBox.send_keys(ip[i], Keys.ENTER)
        time.sleep(1)

        #----- Check if info in table is present -----
        try:
            driver.find_element_by_xpath('/html/body/div[1]/div[2]/div[2]/div/div/div[2]/div/div[2]/div/div/table/tbody/tr/td[1]')
            IOCIPtableEntryPresent = True
        except:
            None
            
        #rows = 1 + len(driver.find_elements_by_xpath("/html/body/div[1]/div[2]/div[2]/div/div/div[2]/div/div[2]/div/div/table/tbody/tr"))
        #columns = len(driver.find_elements_by_xpath("/html/body/div[1]/div[2]/div[2]/div/div/div[2]/div/div[2]/div/div/table/tbody/tr/td"))

        #print(rows + " " + columns)

        try:
            tweetIOCIPData = driver.find_element_by_xpath("/html/body/div[1]/div[2]/div[2]/div/div/div[2]/div/div[2]/div/div/table/tbody/tr/td[3]").text
            print(colored(tweetIOCIPData, "green"))
        except:
            print(colored("[x] No table data for TweetIOC IP Info", "red"))
        print("\n")
        
    urlOfPage = driver.current_url # Get current url of web page for later
    print(urlOfPage)
    print("\n")

    #----- Shut it down -----
    
    driver.close()

    #----- Return Values -----
    return IOCIPtableEntryPresent, tweetIOCIPData

#IOCIPtableEntryPresent, tweetIOCIPData = tweetIOCIP(ip)
#print(IOCIPtableEntryPresent)
#print("\n\n\n")
#print(colored(tweetIOCIPData, "green"))


def alienVaultIPCheck(ip): # alienVault and virusTotal
    #----- Initialize Selenium -----
    if platform == "win32":
        #print(colored("[i] Windows OS Detected", 'blue'))
        gecko = (r"C:/Users/Evan/iCloudDrive/iCloud~md~obsidian/Evan's Apple Vault/Fall 2021 Semester/INFA-713 Managing Security Risks/Semester Project/Python Project 1/firefox-geckodrivers/Windows/geckodriver.exe")
        options = Options()
        options.headless = True
        #binary = FirefoxBinary(r'/Applications/Firefox.app')
        #driver = webdriver.Firefox(options=options, executable_path=gecko) #headless running
        driver = webdriver.Firefox(executable_path=gecko)
    else:
        #print(colored("[i] MacOS Detected", 'blue'))
        #print(colored('\n' + '----- Started -----', 'green'))
        gecko = (r"/Users/evan/Library/Mobile Documents/iCloud~md~obsidian/Documents/Evan's Apple Vault/Fall 2021 Semester/INFA-713 Managing Security Risks/Semester Project/Python Project 1/firefox-geckodrivers/Mac/geckodriver")
        #binary = FirefoxBinary(r'/Applications/Firefox.app')
        driver = webdriver.Firefox(executable_path=gecko)

    for i in range(len(ip)):
        print(ip[i])
        #----- Initialize Values -----
        alienIPEntryPresent = False
        alienIPData = ""

        #----- Use Selenium to Check Tweetioc.com for URL -----
        alienIPURL = 'https://otx.alienvault.com/indicator/ip/' + ip[i]
        
        
        driver.get(alienIPURL)
        time.sleep(2)

        try:
            alienPulse = driver.find_element_by_xpath('//*[@id="indicator-results"]/otx-nav-banner/div/div[1]/div[2]/span').text
            alienIPEntryPresent = True
            print("Pulses = " + alienPulse)
        except:
            print(colored("No Pulses from AlienVault", "red"))
            alienIPEntryPresent = False
            return
        #list = driver.find_elements_by_id('query') # tested, two query id are present on search page
        #print(list)

        try:
            alienDNS = driver.find_element_by_xpath('//*[@id="indicator-results"]/otx-nav-banner/div/div[3]/div[2]/span').text
            print("Passive DNS = " + alienDNS)
            alienIPEntryPresent = True
        except:
            print(colored("No Passive DNS Info from AlienVault", "red"))

        try:
            alienURLS = driver.find_element_by_xpath('//*[@id="indicator-results"]/otx-nav-banner/div/div[4]/div[2]/span').text
            print("URLs = " + alienURLS)
            alienIPEntryPresent = True
        except:
            print(colored("No URLs Info from AlienVault", "red"))

        try:
            alienFiles = driver.find_element_by_xpath('//*[@id="indicator-results"]/otx-nav-banner/div/div[5]/div[2]/span').text
            print("Files = " + alienFiles)
            alienIPEntryPresent = True
        except:
            print(colored("No Files Info from AlienVault", "red"))
        
        urlOfPage = driver.current_url # Get current url of web page for later
        print(urlOfPage)
        print("\n")
        

    driver.close()

#alienVaultIPCheck(ip)



if __name__ == '__main__':
    tweetIOCURL()

