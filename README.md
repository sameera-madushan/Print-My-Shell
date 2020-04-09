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

### Git Installation
```
# clone the repo
$ git clone https://github.com/sameera-madushan/Print-My-Shell.git

# change the working directory to Print-My-Shell
$ cd Print-My-Shell
```

### Usage

```
usage: shell.py [-h] [-i IPADDR] [-p PORTNUM] [-t TYPE] [-l] [-a]

optional arguments:
  -h, --help            show this help message and exit
  -i IPADDR, --ip IPADDR
                        IP address
  -p PORTNUM, --port PORTNUM
                        Port number
  -t TYPE, --type TYPE  Type of the reverse shell to generate
  -l, --list            List all available shell types
  -a, --all             Generate all the shells
```

### Support & Contributions
- Please ⭐️ this repository if this project helped you!
- Contributions of any kind welcome!

## License
MIT ©[sameera-madushan](https://github.com/sameera-madushan)

### References
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
