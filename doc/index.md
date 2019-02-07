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
