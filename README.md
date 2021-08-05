# Print-My-Shell

"Print My Shell" is a python script, wrote to automate the process of generating various reverse shells based on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) and [Pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) reverse shell cheat sheets.

Using this script you can easily generate various types of reverse shells without leaving your command line. This script will come in handy when you are playing [CTF](https://en.wikipedia.org/wiki/Capture_the_flag#Computer_security) like challenges.   

![iaa](https://user-images.githubusercontent.com/55880211/78874353-e461f080-7a69-11ea-848c-32186f1d60fa.gif)

## Available Shell Types
- Bash
- Perl
- Ruby
- Golang
- Netcat
- Ncat
- Powershell
- Awk
- Lua
- Java
- Socat
- Nodejs
- Telnet
- Python

## Git Installation
```
# clone the repo
$ git clone https://github.com/sameera-madushan/Print-My-Shell.git

# change the working directory to Print-My-Shell
$ cd Print-My-Shell
```

## Usage

```
usage: shell.py [-h] [-i IPADDR] [-p PORTNUM] [-t TYPE] [-l] [-a] [-s]

optional arguments:
  -h, --help            show this help message and exit
  -i IPADDR, --ip IPADDR
                        IP address
  -p PORTNUM, --port PORTNUM
                        Port number
  -t TYPE, --type TYPE  Type of the reverse shell to generate
  -l, --list            List all available shell types
  -a, --all             Generate all the shells
  -s, --shellonly       Disables all output other than the first shell of given type
```

## Support & Contributions
- Please ⭐️ this repository if this project helped you!
- Contributions of any kind welcome!

<a href="https://www.buymeacoffee.com/sameeramadushan" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

## License
Print My Shell is made with ♥ by [@_\_sa_miya__](https://twitter.com/__sa_miya__) and it is released under the MIT license.

## References
[Payloads All The Things Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

[Pentestmonkey Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
