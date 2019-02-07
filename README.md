[![Documentation Status](https://readthedocs.org/projects/discovery-tool/badge/?version=latest)](https://discovery-tool.readthedocs.io/en/latest/?badge=latest)
[![Known Vulnerabilities](https://snyk.io/test/github/EmilienPer/Discovery/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/EmilienPer/Discovery?targetFile=requirements.txt)
[![Donate](https://img.shields.io/badge/donate-paypal-orange.svg)](https://www.paypal.me/EmilienPer)
[![Beerpay](https://beerpay.io/EmilienPer/Discovery/badge.svg?style=plastic)](https://beerpay.io/EmilienPer/Discovery)
## Table of Contents
   * [Discovery](#discovery)
   * [Requirement](#requirement)
   * [Installation](#installation)
   * [Options](#options)
   * [Usage](#usage)
   * [Example](#example)
   * [Issues management](#issues-management)
 
## Discovery
Discovery was created to be used for OSP certification.
This tool (inspired by the "reconnoitre" tool: https://github.com/codingo/Reconnoitre) makes it possible to scan hosts finally to obtain a maximum of information on these. It is therefore a recognition tool.
Its mechanism can be summarized as follows:

 For each host:
- Create the exploit, proof and scan folders required for OSCP certification
- Determine open ports and related services
- For each port:
    * List exploits related to the product using the port
    *  Start scans according to the protocol
    * Suggest additional scans asking for human intervention or other exploits
- Write an analysis report (HTML and XML format)
## Requirement
Discovery run on Python 2.7 can't work correctly without the following tools
- Nmap           
- smtp-user-enum 
- whatweb        
- nikto          
- dirb     
## Installation
`sudo pip install discovery`

## Options
| Shortcut | option | Required | Default | Description |
| -------- | ------ | -------- | ------- | ----------- |
| |  <ips>    | X | | The Ip(s) address of the host |
| -o | --output |  | .|The output directory|
| -t | --max_threads | |5 |  The maximum number of host handled in the same time |
| | --cache |  | False |Use cache |
| -a | --all |  | False|Scan all ports | 
| | --css |  | |The CSS file to use into the HTML report| 
| | --javascript_header |  | |  The javascript file to use into the header of the HTML report | 
| | --javascript_tail |  | |  The javascript file to use into  the end of the HTML report |
## Usage
The <ips> param can be 
- An IPv4 address (example: 192.168.0.1)
- An range of IPv4 addresses (example: 192.168.0.0/24 or 192.168.0.1-254)
- A list of IPv4 address separated by ";" (example: 192.168.0.1;198.162.0.2)

Example:
* `discovery 192.168.0.1 -o /root/`,
* `discovery 192.168.0.0/24 -o /root/`
* `discovery 192.168.0.1-254 -o /root/`
* `discovery 192.168.0.1;198.162.0.2 -o /root/`
* `discovery 192.168.0.1 -o /root/ -t 5 --cache --all `
* `discovery 192.168.0.1 -o /root/ --javascript_header javascript_file.js --javascript_tail other_file.js --css shett.css`
## Example
Example of usage can be found in the "examples" directory
## Issues management 
For contributions or suggestions, please [open an Issue](https://github.com/EmilienPer/Discovery/issues/new) and clearly explain, using an example or a use case if appropriate. 