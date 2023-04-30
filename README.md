# ZTE Telnet
Turn on Telnet service of a ZTE router or ONU.

## Requirements
- **Python version:** 2.7 or 3.0+
- **Third-Party Packages:** not required

## Usage
```
usage: ztel.py [-h] [-s] [-u <user>] [-p <pass>] [address]

Turn on Telnet service of a ZTE router or ONU.

positional arguments:
  address     ZTE router IP address, default is 192.168.1.1

options:
  -h, --help  show this help message and exit
  -s          stop Telnet service
  -u <user>   username of ZTE router
  -p <pass>   password of ZTE router
```

## Acknowledgement
- **zte_modem_tools** by douniwan5788 (AGPL-3.0 license)
- **pyAES** by Marti Raudsepp (MIT license)

## License
GNU Affero General Public License v3.0
