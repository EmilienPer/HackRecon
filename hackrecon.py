#!/usr/bin/env python
# -*- coding: utf8 -*-
#        ----------------------------------------------------------------------------------------------
#        |     @@@@@@@   @@@   @@@@@@    @@@@@@@   @@@@@@   @@@  @@@  @@@@@@@@  @@@@@@@   @@@ @@@     |
#        |    @@@@@@@@  @@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  @@@ @@@      |
#        |    @@!  @@@  @@!  !@@       !@@       @@!  @@@  @@!  @@@  @@!       @@!  @@@  @@! !@@      |
#        |    !@!  @!@  !@!  !@!       !@!       !@!  @!@  !@!  @!@  !@!       !@!  @!@  !@! @!!      |
#        |    @!@  !@!  !!@  !!@@!!    !@!       @!@  !@!  @!@  !@!  @!!!:!    @!@!!@!    !@!@!       |
#        |    !@!  !!!  !!!   !!@!!!   !!!       !@!  !!!  !@!  !!!  !!!!!:    !!@!@!      @!!!       |
#        |    !!:  !!!  !!:       !:!  :!!       !!:  !!!  :!:  !!:  !!:       !!: :!!     !!:        |
#        |    :!:  !:!  :!:      !:!   :!:       :!:  !:!   ::!!:!   :!:       :!:  !:!    :!:        |
#        |     :::: ::   ::  :::: ::    ::: :::  ::::: ::    ::::     :: ::::  ::   :::     ::        |
#        |    :: :  :   :    :: : :     :: :: :   : :  :      :      : :: ::    :   : :     :         |
#        ----------------------------------------------------------------------------------------------
__author__ = "Emilien Peretti"
__version__ = "1.1.2"
__doc__ = """
HackRecon was created to be used for OSP certification.                                                  
This tool (inspired by the "reconnoitre" tool: https://github.com/codingo/Reconnoitre)  scan hosts 
 to obtain a maximum of information on these. It is therefore a recognition tool.   
Its mechanism can be summarized as follows:                                                              
     For each host:                                                                                      
          - Create the exploit, proof and scan folders required for OSCP certification                   
          - Determine open ports and related services                                                    
          - For each port:                                                                               
             * List exploits related to the product using the port                                       
             * Start scans according to the protocol                                                     
             * suggest additional scans asking for human intervention or other exploits                  
          - Write an analysis report (HTML and XML format)                                               
"""
__examples__ = ["hackrecon 192.168.0.1 -o /root/",
                "hackrecon 192.168.0.0/24 -o /root/",
                "hackrecon 192.168.0.1-254 -o /root/"
                "hackrecon 192.168.0.1;198.162.0.2 -o /root/",
                "hackrecon 192.168.0.1 -o /root/ -t 5 --cache --all ",
                "hackrecon 192.168.0.1 -o /root/ --javascript_header javascript_"
                "file.js --javascript_tail other_file.js --css shett.css"
                ]

import argparse
import logging
import os
import shutil
import signal
import subprocess
import sys
import textwrap
import enlighten as enlighten

from lxml import etree
from netaddr import *
from threading import Thread

# ------------------------------------------ Commands ------------------------------------------------------------------
NMAP = "nmap -sC -Pn {} -O --disable-arp-ping -sV -oA {} {}"

NMAP_KERBEROS_CMD = "nmap -p {} --script=krb5-enum-users --script-args krb5-enum-users.realm='CHANGEME.local'," \
                    "userdb=/usr/share/seclists/Usernames/Names/names.txt -oA '{}' {}"

NMAP_SNMP_CMD = "nmap -sV -Pn -vv -p{} --script=snmp-netstat,snmp-processes -oA '{}' {}"

SMTP_CMD = "smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top_shortlist.txt" \
           " -t {} -p {}|grep Exists"

NMAP_SMB_USER_ENUM_CMD = "nmap -sV -Pn -vv -p {} --script=smb-enum-users -oA '{}' {}"

NMAP_SMB_VULN_CMD = "nmap -sV -Pn -vv -p {} --script=smb-vuln* --script-args=unsafe=1 -oA '{}' {}"

NMAP_MICROSOFTSQL_CMD = "nmap -vv -sV -Pn -p {} --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes " \
                        "--script-args=mssql.instance-port={},smsql.username-sa,mssql.password-sa -oA '{}' {}"

NMAP_FTP_CMD = "nmap -sV -Pn -vv -p {} --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-syst," \
               "ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oA '{}' {}"

WHATWEB_CMD = "whatweb {} --colour never"

DIRB_CMD = "dirb {} -o {}"

NIKTO_CMD = "nikto -h {} -p {} -output {}"
# ------------------------------------------ other constants -----------------------------------------------------------
CACHE = False
SCAN_DIR = "scans"
SCAN_TOOLS_DIR = "tools"
CSS = None
JAVASCRIPT_HEADER = None
JAVASCRIPT_TAIL = None
BAR_MANAGER = enlighten.get_manager()
processes = []


# ------------------------------------------ common functions ----------------------------------------------------------
class GenericThread(Thread):
    """
    Generic thread
    The response of the function is stored in self.rep
    """
    rep = None

    def __init__(self, function, arguments=None, bar=None):
        """
        :param function: The function to execute
        :param arguments: the arguments of the function
        """
        Thread.__init__(self)
        self.function = function
        self.args = arguments
        self.bar = bar

    def run(self):
        self.rep = self.function(*self.args)
        if self.bar:
            self.bar.update()


def get_port_from_port_tree(port_tree):
    """
    Returns the port number from the xml port
    :param port_tree: the xml port tree
    :return: the port number
    """
    return port_tree.get("portid")


def get_product_from_port_tree(port_tree):
    """
    Returns the product and the version witch is using the corresponding port
    :param port_tree: the xml port tree
    :return: the product, the version
    """
    service = port_tree.find("service")
    product = service.get("product") if "product" in service.attrib else None
    version = service.get("version") if "version" in service.attrib else None
    return product, version


def get_corresponding_port_node_in_tree(new_tree, port_tree):
    """
    Return the port tree of the new xml tree witch is corresponding to the other port tree
    :param new_tree: the new xml tree
    :param port_tree: the port tree to find in the new xml tree
    :return:
    """
    return new_tree.find("host/ports/port[@portid='{}']".format(port_tree.get("portid")))


def add_script_into_port_from_xml_file(port_tree, xml, original_cmd=None):
    """
    Add all script elem in the port tree
    :param port_tree: the xml port tree
    :param xml: the xml tree to parse to find scripts
    :param original_cmd: the command witch generated the xml
    :return: None
    """
    if os.path.exists(xml) and os.path.getsize(xml) != 0:
        for script in get_corresponding_port_node_in_tree(etree.parse(xml).getroot(), port_tree).findall('script'):
            port_tree.append(script)
            if original_cmd is not None:
                script.set("CMD", original_cmd)


def add_suggestions_in_port_tree(port_tree, suggestions):
    """
    Add all suggestion into the port tree in a Element called "Suggestion"
    :param port_tree: the xml port tree
    :param suggestions: a list of suggestions
    :return: None
    """
    suggestions_node = etree.Element("suggestions")
    for suggestion in suggestions:
        suggestion_node = etree.SubElement(suggestions_node, 'suggestion')
        suggestion_node.text = suggestion
    port_tree.append(suggestions_node)


def execute(cmd):
    """
    Execute the shell command and return the output
    :param cmd: the shell command
    :return: the output or None if error
    """
    logging.info(cmd)
    rep = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    processes.append(rep)
    return rep.stdout.read()


def execute_and_save(cmd, filename, mode="w"):
    """
    Execute the command and save the result into the file before returning it
    :param mode: the file opening mode
    :param cmd: the shell command
    :param filename: the path to the file
    :return: the output of the command
    """
    with open(filename, mode) as f:
        rep = execute(cmd)
        f.write("// command: {}".format(cmd))
        f.write(rep)
        return rep


def get_ips_from_string(ip_string):
    """
    Return a list of ip
    :param ip_string: an ip or a range of ip (X.X.X.X/Y or X.X.X.X-Z or X.X.X.X;Y.Y.Y.Y.Y;Z.Z.Z.Z)
    :return: a list of ip address
    """
    if "/" in ip_string:
        return [str(ip_address) for ip_address in list(IPNetwork(ip_string))]
    elif "-" in ip_string:
        tmp = ip_string.split("-")
        start_ip = tmp[0]
        tmp2 = start_ip.split(".")
        end_ip = "{}.{}.{}.{}".format(tmp2[0], tmp2[1], tmp2[2], tmp[1])
        return [str(ip_address) for ip_address in iter_iprange(start_ip, end_ip, step=1)]
    elif ";" in ip_string:
        return ip_string.split(';')
    else:
        return [ip_string]


def make_folder_for_ip(ip_address, directory):
    """
    Create a directory with the following folders :
        - scans
        -tools
        - proofs
        - exploit
    :param ip_address:the ip address
    :param directory: the parent directory
    :return: the new path
    """
    base = os.path.join(directory, ip_address)
    scan_path = os.path.join(base, SCAN_DIR)
    try:
        if not os.path.exists(base):
            os.mkdir(base)
        if not os.path.exists(scan_path):
            os.mkdir(scan_path)
        if not os.path.exists(os.path.join(scan_path, SCAN_TOOLS_DIR)):
            os.mkdir(os.path.join(scan_path, SCAN_TOOLS_DIR))
        if not os.path.exists(os.path.join(base, "exploit")):
            os.mkdir(os.path.join(base, "exploit"))
        if not os.path.exists(os.path.join(base, "proof")):
            os.mkdir(os.path.join(base, "proof"))
    except OSError:
        return None
    return base


def remove_folder(folder_path):
    """
    Remove the folder
    :param folder_path: the path of the folder
    :return:
    """
    # check if folder exists
    if os.path.exists(folder_path):
        # remove if exists
        shutil.rmtree(folder_path)


def host_tree_to_html(ip_address, host_tree, base):
    """
    Transform an xml host tree into a html tree
    :param ip_address: the ip address o the host
    :param host_tree: the xml host tree
    :param base: the base dir to store the generated files (HTML and XMl)
    :return:
    """
    output_xml = os.path.join(os.path.join(base, SCAN_DIR), "host.xml")
    with open(output_xml, "w") as f:
        f.write(etree.tostring(host_tree))
    html = etree.Element("html")
    head = etree.SubElement(html, "head")
    etree.SubElement(head, "title").text = "HackRecon: {}".format(ip_address)
    if CSS:
        etree.SubElement(head, "link", attrib={"rel": "stylesheet", "type": "text/css", "href": CSS})
    if JAVASCRIPT_HEADER:
        etree.SubElement(head, "script", attrib={"src": JAVASCRIPT_HEADER})
    body = etree.SubElement(html, "body")

    etree.SubElement(body, "h1", attrib={"align": "center"}).text = "HackRecon: {}".format(ip_address)
    os_name = ""
    accuracy = 0

    for os_match in host_tree.findall("os/osmatch"):
        if float(os_match.get("accuracy")) > accuracy:
            accuracy = float(os_match.get("accuracy"))
            os_name = os_match.get("name")
    tcp_port = []
    udp_port = []
    tcp = []
    udp = []
    for port_tree in host_tree.find('ports').findall('port'):
        if port_tree.get("protocol") == "tcp":
            tcp_port.append(port_tree.get("portid"))
            tcp.append(port_tree.find("service").get("name"))
        elif port_tree.get("protocol") == "udp":
            udp_port.append(port_tree.get("portid"))
            udp.append(port_tree.find("service").get("name"))

    summary = etree.SubElement(body, "table", attrib={"class": "summary"})
    head = etree.SubElement(summary, "tr", attrib={"class": "head"})
    etree.SubElement(head, "td").text = "Host"
    etree.SubElement(head, "td").text = "OS"
    etree.SubElement(head, "td").text = "Ports"
    etree.SubElement(head, "td").text = "Services"
    line = etree.SubElement(summary, "tr", attrib={"class": "line"})
    etree.SubElement(line, "td").text = ip_address
    etree.SubElement(line, "td").text = os_name
    port_ul = etree.SubElement(etree.SubElement(line, "td"), 'ul')
    service_ul = etree.SubElement(etree.SubElement(line, "td"), 'ul')
    if len(tcp_port) != 0:
        etree.SubElement(port_ul, "li", attrib={"class": "tcp_port"}).text = "TCP: {}".format(",".join(tcp_port))
        etree.SubElement(service_ul, "li", attrib={"class": "tcp_services"}).text = "TCP: {}".format("/".join(tcp))
    if len(udp_port) != 0:
        etree.SubElement(port_ul, "li", attrib={"class": "udp_port"}).text = "UDP: {}".format(",".join(udp_port))
        etree.SubElement(service_ul, "li", attrib={"class": "udp_services"}).text = "UDP: {}".format("/".join(udp))
    if host_tree.find('ports').findall('port'):
        for port_tree in host_tree.find('ports').findall('port'):
            service = port_tree.find("service")
            etree.SubElement(body, "h2").text = "{} ({}:{} - {})".format(port_tree.get("portid"),
                                                                         service.get("name"), service.get("product"),
                                                                         service.get("version"))
            table_summary_port = etree.SubElement(body, "table", attrib={"class": "summary_table"})
            table_summary_port_head = etree.SubElement(table_summary_port, "tr")
            etree.SubElement(table_summary_port_head, "td", attrib={"class": "state title"}).text = "State"
            etree.SubElement(table_summary_port_head, "td", attrib={"class": "cpe title"}).text = "CPE"
            table_summary_port_body = etree.SubElement(table_summary_port, "tr")
            etree.SubElement(table_summary_port_body, "td", attrib={"class": "state"}).text = port_tree.find(
                "state").get("state")
            try:
                etree.SubElement(table_summary_port_body, "td", attrib={"class": "cpe"}).text = service.find(
                    "cpe").text
            except:
                etree.SubElement(table_summary_port_body, "td", attrib={"class": "cpe"}).text = "/"
            exploit_table = etree.SubElement(body, "table", attrib={"class": "exploits_table"})
            exploit_table_head = etree.SubElement(exploit_table, "tr")
            etree.SubElement(exploit_table_head, "td", attrib={"class": "exploit title"}).text = "EXPLOIT NAME"
            etree.SubElement(exploit_table_head, "td", attrib={"class": "exploit title"}).text = "EXPLOIT PATH"
            for exploit in port_tree.findall("exploits/exploit"):
                line = etree.SubElement(exploit_table, "tr")
                etree.SubElement(line, "td", attrib={"class": "exploit_name"}).text = exploit.get("name")
                list_path = etree.SubElement(etree.SubElement(line, "td", attrib={"class": "exploit_path"}), 'ul')
                if exploit.get("path"):
                    etree.SubElement(list_path, "li", attrib={"class": "path"}).text = exploit.get("path")
                if exploit.get("url"):
                    etree.SubElement(etree.SubElement(list_path, "li", attrib={"class": "url"}), 'a',
                                     attrib={"href": exploit.get("url")}).text = exploit.get("url")

            if port_tree.findall("script"):
                for script_tree in port_tree.findall("script"):
                    script_id = script_tree.get("id")
                    script_output = script_tree.get("output")
                    cmd = script_tree.get("CMD")
                    script_table = etree.SubElement(body, "table", attrib={"class": "script_table"})
                    script_table_l1 = etree.SubElement(script_table, "tr", attrib={"class": "script_first_line"})
                    script_table_l2 = etree.SubElement(script_table, "tr", attrib={"class": "script_second_line"})
                    etree.SubElement(etree.SubElement(script_table, "tr", attrib={"class": "script_second_line"}), 'td',
                                     attrib={"class": "cmd"}).text = cmd
                    etree.SubElement(script_table_l1, "td",
                                     attrib={"rowspan": "3", 'class': "script_tag"}).text = "SCRIPT"
                    etree.SubElement(script_table_l1, "td",
                                     attrib={"rowspan": "3", "class": "script_id"}).text = script_id
                    etree.SubElement(script_table_l1, "td", attrib={"class": "script_output"}).text = script_output
                    text = etree.SubElement(script_table_l2, "td", attrib={"class": "script_content"})
                    script_child = script_tree.getchildren()
                    if len(script_child) != 0:
                        for child in script_child:
                            text.append(child)
                    else:
                        text.text = script_tree.text
            if port_tree.find("suggestions") is not None:
                suggestions_table_line = etree.SubElement(
                    etree.SubElement(body, "table", attrib={"class": "suggestions_table"}), "tr")
                etree.SubElement(suggestions_table_line, "td", attrib={"class": "suggestions_tag"}).text = "SUGGESTIONS"
                suggestions = etree.SubElement(
                    etree.SubElement(suggestions_table_line, "td", attrib={"class": "suggestions"}), "ul",
                    attrib={"class": "suggestions_list"})
                for suggestion in port_tree.find("suggestions"):
                    etree.SubElement(suggestions, "li", attrib={"class": "suggestion"}).text = suggestion.text
                etree.SubElement(body, "br")
    if JAVASCRIPT_TAIL:
        etree.SubElement(body, "script", attrib={"src": JAVASCRIPT_TAIL})
    etree.SubElement(body, "hr")
    etree.SubElement(body, "p").text = "Report generated by HackRecon (Tool created by Emilien Peretti)"
    output_html = os.path.join(os.path.join(base, SCAN_DIR), "host.html")
    with open(output_html, "w") as f:
        f.write(etree.tostring(html))


# ---------------------------------------------- scanners --------------------------------------------------------------
def nmap(ip_address, base, all_port):
    """
    Scans the host and store the result in base before return the xml
    :param all_port: true if scan all port
    :param ip_address: the ip address of the host
    :param base: the path of folder for the host
    :return: the xml tree result of the NMAP scan
    """
    filename = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR), "nmap_{}".format(ip_address))
    xml = "{}.xml".format(filename)
    cmd = NMAP.format("-p-" if all_port else "", filename, ip_address)
    if not (CACHE and os.path.exists(xml)):
        execute(cmd)
    if os.path.exists(xml) and os.path.getsize(xml) != 0:
        root = etree.parse(xml).getroot().find("host")
        for script in root.findall("ports/port/script"):
            script.set("CMD", cmd)
        return xml, root
    return None


def nikto(ip_address, port_tree, base, url):
    """
    Execute the nikto command
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :param url: the url of the target of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                               "nikto_{}_{}.xml".format(ip_address, port))
    port = get_port_from_port_tree(port_tree)
    cmd = NIKTO_CMD.format(url, port, output_file)
    if not (CACHE and os.path.exists(output_file)):
        execute(cmd)
    script_node = etree.Element("script", attrib={"id": "TOOL_nikto", "output": "", 'CMD': cmd})
    ul = etree.SubElement(script_node, "ul", attrib={"class": "nikto_list"})
    for item in etree.parse(output_file).getroot().findall("scandetails/item"):
        if item.find('description').text != "#TEMPL_MSG#":
            etree.SubElement(ul, "li", attrib={"class": "nikto_elem"}).text = "{} : {}".format(item.get("osvdbid"),
                                                                                               item.find(
                                                                                                   'description').text)
    port_tree.append(script_node)


def dirb(ip_address, port_tree, base, url, port):
    """
    Execute the dib command
    :param port: the port to use into the scan
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :param url: the url of the target of the scan
    :return:
    """
    output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                               "dirb_{}_{}.txt".format(ip_address, port))
    cmd = DIRB_CMD.format(url, output_file)
    if not (CACHE and os.path.exists(output_file)):
        if os.path.exists(output_file):
            os.remove(output_file)
        execute(cmd)
    script_node = etree.Element("script", attrib={"id": "TOOL_dirb", "output": "", "CMD": cmd})
    content = etree.SubElement(script_node, "ul")
    with open(output_file, "r") as f:
        dirb_out = f.read()
        for line in dirb_out.split("\n"):
            etree.SubElement(content, "p", attrib={"class": "dirb_line"}).text = line
    port_tree.append(script_node)
    out = [url]
    for line in dirb_out.split("\n"):
        if "==> DIRECTORY: " in line:
            out.append(line[15:])
    return out


def scan_dirb(ip_address, port_tree, base, url, port):
    """
    Execute the dirb scan and then, for each directory found on the target, execute the whatweb command
    :param port: the port to use into the scan
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :param url: the url of the target of the scan
    :return:
    """
    dirb_output = dirb(ip_address, port_tree, base, url, port)
    for elem in dirb_output:
        cmd = WHATWEB_CMD.format(elem)
        whatweb = execute(cmd)
        script_node = etree.Element("script", attrib={"id": "TOOL_whatweb",
                                                      "output": "{}==> SUGGESTION :searchsploit".format(elem),
                                                      "CMD": cmd})
        content = etree.SubElement(script_node, "elem")
        content.text = str(whatweb)
        port_tree.append(script_node)


def scan_http(ip_address, port_tree, base):
    """
    Scan for HTTP protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    method = port_tree.find("service").get("name")
    prefix = "https://" if (method == "https" or method == "http/s") else "http://"
    port = get_port_from_port_tree(port_tree)
    url = "{}{}:{}/".format(prefix, ip_address, port)
    thread_nikto = GenericThread(function=nikto, arguments=(ip_address, port_tree, base, url))
    thread_dirb = GenericThread(function=scan_dirb, arguments=(ip_address, port_tree, base, url, port))
    thread_nikto.start()
    thread_dirb.start()
    thread_nikto.join()
    thread_dirb.join()


def scan_ftp(ip_address, port_tree, base):
    """
    Scan for FTP protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR), "ftp_{}_{}".
                               format(ip_address, port))
    cmd = NMAP_FTP_CMD.format(port, output_file, ip_address)
    if not (CACHE and os.path.exists("{}.xml".format(output_file))):
        execute(cmd)
    add_script_into_port_from_xml_file(port_tree, "{}.xml".format(output_file), cmd)
    add_suggestions_in_port_tree(port_tree,
                                 ["hydra -L USER_LIST -P PASS_LIST -f -o {} -u {} -s {} ftp".format(
                                     os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                                                  "hydra_ftp_{}.txt".format(ip_address)), ip_address, port)])


def scan_dns(ip_address, port_tree, base):
    """
     Scan for DNS protocol
     :param ip_address: the target ip address
     :param port_tree: the xml port tree of the port to use into the nikto scan
     :param base: the base directory to store the result of the scan
     :return:
     """
    add_suggestions_in_port_tree(port_tree,
                                 ["dnsrecon -t axfr -d {} > {}".format(ip_address, os.path.join(
                                     os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                                     "dns_recon_{}.txt".format(ip_address)))])


def scan_microsoftsql(ip_address, port_tree, base):
    """
    Scan for Microsoftsql protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                               "microsoftsql_{}".format(ip_address))
    cmd = NMAP_MICROSOFTSQL_CMD.format(
        port, port, output_file, ip_address)
    if not (CACHE and os.path.exists("{}.xml".format(output_file))):
        execute(cmd)
    add_script_into_port_from_xml_file(port_tree, "{}.xml".format(output_file), cmd)


def scan_smb(ip_address, port_tree, base):
    """
    Scan for SMB protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    try:
        output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                                   "smb_vuln_{}".format(ip_address, port))
        cmd = NMAP_SMB_VULN_CMD.format(
            port, output_file, ip_address)
        if not (CACHE and os.path.exists("{}.xml".format(output_file))):
            execute(cmd)
        add_script_into_port_from_xml_file(port_tree, "{}.xml".format(output_file), cmd)
    except:
        pass
    try:
        output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                                   "smb_enum_user_{}_{}".format(ip_address, port))
        cmd = NMAP_SMB_USER_ENUM_CMD.format(port, output_file, ip_address)
        if not (CACHE and os.path.exists("{}.xml".format(output_file))):
            execute(cmd)
        add_script_into_port_from_xml_file(port_tree, "{}.xml".format(output_file), cmd)
    except:
        pass
    out = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                       "enum4linux_{}.txt".format(ip_address))
    add_suggestions_in_port_tree(port_tree, ["enum4linux -a {} | tee {}".format(ip_address, out)])


def scan_smtp(ip_address, port_tree, base):
    """
    Scan for SMTP protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    try:
        output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                                   "smtp_user_enum_{}_{}.txt".format(ip_address, port))
        cmd = SMTP_CMD.format(ip_address, port)
        if not (CACHE and os.path.exists(output_file)):
            smtp_user_enum = execute_and_save(cmd, output_file)
        else:
            with open(output_file, "r") as f:
                smtp_user_enum = f.read()
        script_node = etree.Element("script", attrib={"id": "TOOL_smtp_user_enum", "output": "", "CMD": cmd})
        content = etree.SubElement(script_node, "elem")
        content.text = smtp_user_enum
        port_tree.append(script_node)
    except:
        pass


def scan_snmp(ip_address, port_tree, base):
    """
    Scan for SNMP protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    try:
        output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                                   "nmap_snmp_{}_{}".format(ip_address, port))
        cmd = NMAP_SNMP_CMD.format(
            port, output_file, ip_address)
        if not (CACHE and os.path.exists("{}.xml".format(output_file))):
            execute(cmd)
        add_script_into_port_from_xml_file(port_tree, "{}.xml".format(output_file), cmd)
    except:
        pass
    out = os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR)
    add_suggestions_in_port_tree(port_tree,
                                 ["onesixtyone {} > {}".format(ip_address, os.path.join(out, "onesixtyone_{}.txt"
                                                                                        .format(ip_address))),
                                  "snmpwalk -c public -v1 {} > {}".format(ip_address,
                                                                          os.path.join(out,
                                                                                       "snmpwalk_{}.txt".format(
                                                                                           ip_address)))])


def scan_kerberos(ip_address, port_tree, base):
    """
    Scan for Kerberos protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    try:
        output_file = os.path.join(os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                                   "nmap_snmp_{}_{}".format(ip_address, port))
        cmd = NMAP_KERBEROS_CMD.format(
            port, output_file, ip_address)
        if not (CACHE and os.path.exists("{}.xml".format(output_file))):
            execute(cmd)
        add_script_into_port_from_xml_file(port_tree, "{}.xml".format(output_file), cmd)
    except:
        pass


def scan_telnet(ip_address, port_tree, base):
    """
    Scan for Telnet protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    add_suggestions_in_port_tree(port_tree,
                                 ["ncat -nv {} {} > {}".format(ip_address, port, os.path.join(
                                     os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR),
                                     "telnet_{}.txt".format(ip_address)))])


def scan_remote_desktop(ip_address, port_tree, _):
    """
    Scan for rdp protocol
    :param _: what you want
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :return:
    """
    add_suggestions_in_port_tree(port_tree,
                                 ["ncrack -vv --user administrator -P PASS_LIST rdp://{}".format(ip_address),
                                  "crowbar -b rdp -u -s {}/32 -U USER_LIST -C PASS_LIST".format(ip_address),
                                  "for username in $(cat USER_LIST); do for password in $(cat PASS_LIST) do; "
                                  "rdesktop -u $username -p $password {}; done; done;".format(ip_address)])


def scan_ssh(ip_address, port_tree, base):
    """
    Scan for SSH protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    port = get_port_from_port_tree(port_tree)
    output = os.path.join(os.path.join(base, SCAN_DIR), SCAN_TOOLS_DIR)
    add_suggestions_in_port_tree(port_tree,
                                 ["medusa -u root -P /usr/share/wordlists/rockyou.txt "
                                  "-e ns -h {} - {} -M ssh".format(ip_address, port),
                                  "hydra -f -V -t 1 -l root -P "
                                  "/usr/share/wordlists/rockyou.txt -s {} {} ssh".format(port, ip_address),
                                  "ncrack -vv -p {} --user root -P PASS_LIST {}".format(port, ip_address),
                                  "nmap {} -p {} -sV --script=ssh-hostkey -oA "
                                  "'{}'".format(ip_address,
                                                port,
                                                os.path.join(output,
                                                             "ssh_hostkey_{}".format(
                                                                 ip_address)))])


def scan_msrpc(ip_address, port_tree, _):
    """
    Scan for MSRPC protocol
    :param _: what you want
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :return:
    """
    add_suggestions_in_port_tree(port_tree,
                                 ["rpcclient -U \"\" {}".format(ip_address)])


def scan_netbios_ssn(ip_address, port_tree, base):
    """
    Scan for netbios protocol
    :param ip_address: the target ip address
    :param port_tree: the xml port tree of the port to use into the nikto scan
    :param base: the base directory to store the result of the scan
    :return:
    """
    scan_smb(ip_address, port_tree, base)
    add_suggestions_in_port_tree(port_tree,
                                 ["nmblookup -A {}".format(ip_address),
                                  "smbclient //MOUNT/share -I {} N".format(ip_address),
                                  "smbclient -L //{}".format(ip_address),
                                  "enum4linux -a {}".format(ip_address),
                                  "rpcclient -U \"\" {}".format(ip_address)])


def scan_ports(ip_address, host_tree, output, bar):
    """
    Scan all port of the host
    :param ip_address: the ip address of the host
    :param host_tree: the xml host tree
    :param output: the output directory for all scan
    :param bar: the progress bar to update
    :return:
    """
    threads_list = []
    for port in host_tree.find('ports').findall('port'):
        if port.find("state").get('state') == 'open':
            if port.find("service").get("name") in protocol_handler:
                t = GenericThread(function=protocol_handler[port.find("service").get("name")],
                                  arguments=(ip_address, port,
                                             output),
                                  bar=bar)
                threads_list.append(t)
                t.start()
            else:
                bar.update()
        else:
            bar.update()
        add_exploit_for_port(port)

    for t in threads_list:
        t.join()


def scan(ip_address, output, all_port):
    """
    Scan the host
    :param all_port: True if all port must be scanned
    :param ip_address: the ip address of the host
    :param output: the base folder for the host
    :return:
    """

    nmap_xml, host_tree = nmap(ip_address, output, all_port)
    if host_tree is not None:
        ports = host_tree.find('ports').findall('port')
        bar = BAR_MANAGER.counter(total=len(ports), desc="Host {}".format(ip_address))
        if len(ports) != 0:
            scan_ports(ip_address, host_tree, output, bar)
            host_tree_to_html(ip_address, host_tree, output)
    else:
        remove_folder(output)


protocol_handler = {
    "http": scan_http,
    "https": scan_http,
    "http/s": scan_http,
    "ftp": scan_ftp,
    "microsoftsql": scan_microsoftsql,
    "smb": scan_smb,
    "smtp": scan_smtp,
    "snmp": scan_snmp,
    "keberos": scan_kerberos,
    "dns": scan_dns,
    "telnet": scan_telnet,
    "remotedesktop": scan_remote_desktop,
    "ssh": scan_ssh,
    "msrpc": scan_msrpc,
    "netbios-ssn": scan_netbios_ssn

}


# ---------------------------------------- Signals ---------------------------------------------------------------------
def signal_handler(signals, frame):
    """
    Signal handler Ctrl+C
    :param signals: the signal
    :param frame: the frame
    :return:
    """
    print signals, frame
    for process in processes:
        try:
            process.kill()
        except OSError:
            pass
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# ----------------------------------------- Exploits -------------------------------------------------------------------
def compare_version(first, second):
    """
    Compare the versions and return -1 if the first version is older, 0 if the versions are equal
    , 1 if the first version is newer
    :param first: the first version string
    :param second: the second version string
    :return:
    """
    split_first = first.replace("p", ".").split(".")
    split_second = second.replace("p", ".").split(".")
    for index in range(min(len(split_first), len(split_second))):
        if split_first[index] == "x" or split_second[index] == "x":
            return 0
        if float(split_first[index]) < float(split_second[index]):
            return -1
        if float(split_first[index]) > float(split_second[index]):
            return 1
    if len(split_first) > len(split_second):
        return 1
    elif len(split_first) < len(split_second):
        return -1
    else:
        return 0


def is_version(string):
    """
    Return True if the string can be a version number
    :param string: the string to analyse
    :return:
    """
    for elem in string.replace("p", ".").split("."):
        try:
            if elem != "x":
                int(elem)
        except:
            return False
    return True


def is_version_vulnerable_to(version, name):
    """
    Returns True if the version is vulnerable to the exploit based on the version number
    :param version: the version string
    :param name: the exploit name
    :return:
    """
    split_name = name.replace("/", " ").split(" ")
    split_name.remove("")
    for index in range(len(split_name)):
        if is_version(split_name[index]):
            if compare_version(version, split_name[index]) == 0:
                return True
            elif index >= 1 and split_name[index - 1] == "<":
                if index >= 2 and is_version(split_name[index - 2]):
                    if compare_version(version, split_name[index - 2]) >= 0 >= compare_version(version,
                                                                                               split_name[index]):
                        return True
                else:
                    return True


def get_exploit_for_product(product, version=None):
    """
    Returns a list of exploits for the product
    :param product: the product to consider
    :param version: the version of the product
    :return:
    """
    exploits = {}
    for line in execute("searchsploit {} --colour".format(product)).split("\n")[4:-2]:
        name, path_to_exploit = line.split("|")
        key = name.replace(" ", '')
        if version is None or is_version_vulnerable_to(version, name):
            exploits[key] = [name, path_to_exploit, None]
    for line in execute("searchsploit {} --colour -w".format(product)).split("\n")[4:-2]:
        name, web = line.split("|")
        key = name.replace(" ", '')
        if key in exploits.keys():
            exploits[key][2] = web
        elif version is None or is_version_vulnerable_to(version, name):
            exploits[key] = [name, None, web]
    return exploits


def add_exploit_for_port(port_tree):
    """
    Add exploits witch can be used to attack the port into the port tree
    :param port_tree: the xml port tree
    :return:
    """
    service = port_tree.find("service")
    product = service.get("product")
    version = service.get("version")
    exploits_node = etree.SubElement(port_tree, "exploits")
    exploits = get_exploit_for_product(product, version)
    for exploit in exploits.keys():
        attrib = {}
        if exploits[exploit][0]:
            attrib["name"] = exploits[exploit][0]
        if exploits[exploit][1]:
            attrib["path"] = exploits[exploit][1]
        if exploits[exploit][2]:
            attrib["url"] = exploits[exploit][2]
        etree.SubElement(exploits_node, "exploit", attrib=attrib)


# ---------------------------------------  Main ------------------------------------------------------------------------
if __name__ == "__main__":
    print("        ---------------------------------------------------------------------------------------------- ")
    print("        |     @@@@@@@   @@@   @@@@@@    @@@@@@@   @@@@@@   @@@  @@@  @@@@@@@@  @@@@@@@   @@@ @@@     | ")
    print("        |    @@@@@@@@  @@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  @@@ @@@      | ")
    print("        |    @@!  @@@  @@!  !@@       !@@       @@!  @@@  @@!  @@@  @@!       @@!  @@@  @@! !@@      | ")
    print("        |    !@!  @!@  !@!  !@!       !@!       !@!  @!@  !@!  @!@  !@!       !@!  @!@  !@! @!!      | ")
    print("        |    @!@  !@!  !!@  !!@@!!    !@!       @!@  !@!  @!@  !@!  @!!!:!    @!@!!@!    !@!@!       | ")
    print("        |    !@!  !!!  !!!   !!@!!!   !!!       !@!  !!!  !@!  !!!  !!!!!:    !!@!@!      @!!!       | ")
    print("        |    !!:  !!!  !!:       !:!  :!!       !!:  !!!  :!:  !!:  !!:       !!: :!!     !!:        | ")
    print("        |    :!:  !:!  :!:      !:!   :!:       :!:  !:!   ::!!:!   :!:       :!:  !:!    :!:        | ")
    print("        |     :::: ::   ::  :::: ::    ::: :::  ::::: ::    ::::     :: ::::  ::   :::     ::        | ")
    print("        |    :: :  :   :    :: : :     :: :: :   : :  :      :      : :: ::    :   : :     :         | ")
    print("        ---------------------------Emilien Peretti-----------------------V: 1.0----------------------- ")
    # Arguments
    parser = argparse.ArgumentParser(description=textwrap.dedent('''\
                                    Useful to discover your target(s).
                                        Example:
                                            $ {} 192.168.0.1 -o /root/
                                            $ {} 192.168.0.0/24 -o /root/
                                            $ {} 192.168.0.1-254 -o /root/
                                            $ {} 192.168.0.1;198.162.0.2 -o /root/
                                    '''.format(sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0])))
    parser.add_argument("ips", help="The ips")
    parser.add_argument('-o', '--output', help='The output directory', dest="out", default=".")
    parser.add_argument('-t', '--max_threads', help='The maximum number of host handled in the same time',
                        dest="max_threads", default=5)
    parser.add_argument('--css', help='The CSS file to use into the HTML report', dest="css", default=None)
    parser.add_argument('--javascript_header', help='The javascript file to use into the header', dest="javascript_h",
                        default=None)
    parser.add_argument('--javascript_tail', help='The javascript file to use into the end of the html',
                        dest="javascript_t",
                        default=None)
    parser.add_argument("--cache", action='store_true', help='Use cache', dest="cache", default=False)
    parser.add_argument('-a', "--all", action='store_true', help='Scan all ports', dest="ports", default=False)
    args = parser.parse_args()
    # Configuration
    print ("The result will be stored in : {}".format(os.path.abspath(args.out)))
    CACHE = args.cache
    CSS = args.css
    if hasattr(args, "javascript_h"):
        JAVASCRIPT_HEADER = args.javascript_h
    if hasattr(args, "javascript_t"):
        JAVASCRIPT_TAIL = args.javascript_t
    # Mains part
    threads = []
    ips_list = get_ips_from_string(args.ips)
    split_list = [ips_list[i * args.max_threads:(i + 1) * args.max_threads] for i in
                  range((len(ips_list) + args.max_threads - 1) // args.max_threads)]
    logging.basicConfig(filename=os.path.join(args.out, "hackrecon.log"), level=logging.INFO)
    for ip_list in split_list:
        part_bar = BAR_MANAGER.counter(total=len(ip_list),
                                       desc="Part {}/{}".format(split_list.index(ip_list), len(split_list)))
        for ip in ip_list:
            path = make_folder_for_ip(ip, args.out)
            if path:
                threads.append(GenericThread(function=scan, arguments=(ip, path, args.ports), bar=part_bar))
                threads[-1].start()
        for thread in threads:
            thread.join()
