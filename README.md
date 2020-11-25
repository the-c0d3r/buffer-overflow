# Buffer Overflow Tools

This tool is created in order to allow penetration testers / researchers to quickly test out simple buffer overflows, without having to write a line of code. 

The user will only need to enter bad characters to filter out, as well as the EIP address to overwrite to, and the tool will generate buffer string to return a reverse shell. 

## Usage
```
Buffer overflow exploit testing tool

optional arguments:
  -h, --help              show this help message and exit  
  --prefix PREFIX         prefix of the string to send  
  --suffix SUFFIX         suffix of the string to send (default: "\r\n")
  --ip IP                 target ip address
  --port PORT             target port to exploit
  --rport RPORT           reverse shell port (default: 443)
  --interface INTERFACE   the interface to use (default: "tun0")
```
