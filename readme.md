# BushFire PCAP Parser and OSINT Scraper
## Video Demo:
https://vimeo.com/651752389

## What It Does
- Grabs all HTTP information from a PCAP like URI, URL, IP sources, IP destinations, and IPs mentioned in HTTP packets
- Runs this informaiton through sites like TweetIOC, AlienVault, and GreyNoise, and highlights the results

## Requirements to Install
### Python Packages Required
- Selenium
- RE
- GreyNoise
- DPKT
- Termcolor
- Time
- Warnings
- PrettyTable
- Shodan
- OS
- Sys

### Programs Required to be Installed
- Firefox
- Correct Geckodriver for your OS (MacOS and Windows Geckodriver included in this repo)

### Operating Systems This is Working On
- MacOS Big Sur (Fully working)
- Windows 10 (Having some problems with GeckoDriver)