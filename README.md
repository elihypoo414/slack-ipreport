# slack-ipreport
Use criminalip api & slack api to analyze domain

## Introduction:
Inspired by URLScanBot([https://github.com/jaredscottwilson/URLScanBot](https://github.com/jaredscottwilson/URLScanBot)), a program that retrieves information about URLs using the URLScan API and sends it to a Slack channel, I created a program that utilizes CriminalIP, an OSINT search engine that fetches diverse information about URLs and IP addresses. Together with Slack's API, this program sends the aforementioned information to a Slack channel.

Requires: Python 3.7+

# Prerequisites
slack api / criminalip api (get it on the website - https://www.criminalip.io)

## Install:

	$ git clone https://github.com/elihypoo414/slack-ipreport.git
	$ cd download-folder

## Run:

	$ python main.py --k <Criminal API Key> --s <Search Query> --c <slack channel name> --t <slack bot token>

## Contributors : 
						 
GitHub : [jaredscottwilson](https://github.com/jaredscottwilson)

**DISCLAIMER :-
This script is only for penetration testing and security research. I will not be responsible if you use it for any illegal activities.**
