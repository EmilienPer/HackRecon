[![Documentation Status](https://readthedocs.org/projects/discovery-tool/badge/?version=latest)](https://discovery-tool.readthedocs.io/en/latest/?badge=latest)
[![Known Vulnerabilities](https://snyk.io/test/github/EmilienPer/Discovery/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/EmilienPer/Discovery?targetFile=requirements.txt)
[![Donate](https://img.shields.io/badge/donate-paypal-orange.svg)](https://www.paypal.me/EmilienPer)
[![Beerpay](https://beerpay.io/EmilienPer/Discovery/badge.svg?style=plastic)](https://beerpay.io/EmilienPer/Discovery)
## Table of Contents
   * [Discovery](#discovery)
   * [Requirement](#requirement)
   * [Installation](#installation)
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

## Usage

## Example

## Issues management