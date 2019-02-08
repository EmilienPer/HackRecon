The <ips> parameter can be 
- An IPv4 address (example: 192.168.0.1)
- An range of IPv4 addresses (example: 192.168.0.0/24 or 192.168.0.1-254)
- A list of IPv4 address separated by ";" (example: 192.168.0.1;198.162.0.2)

Example:
* `hackrecon 192.168.0.1 -o /root/`,
* `hackrecon 192.168.0.0/24 -o /root/`
* `hackrecon 192.168.0.1-254 -o /root/`
* `hackrecon 192.168.0.1;198.162.0.2 -o /root/`
* `hackrecon 192.168.0.1 -o /root/ -t 5 --cache --all `
* `hackrecon 192.168.0.1 -o /root/ --javascript_header javascript_file.js --javascript_tail other_file.js --css shett.css`
* `hackrecon 192.168.0.1 -o /root/ -t 5 --cache --all --full all`
* `hackrecon 192.168.0.1 -o /root/ -t 5 --cache --all  --full http;ssh;smb`