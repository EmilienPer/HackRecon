
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
| | --full |  | |  Use all nmap nse scrip for the protocol. The value can be "all" or a list of protocol separated by ";"  |