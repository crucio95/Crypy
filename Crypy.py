import binascii
import argparse
from getpass import getpass
import sys
from module import aes

#Display the banner
with open("banner.txt") as f:
    print(f.read())

#Parser for the arguments
parser = argparse.ArgumentParser(description="Simple Python's script for Encrypting and Decrypting Data", epilog="And That's All! Start Encrypting!")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-d", "--decrypt", action="store_true", help="use this for decripting data", default=0)
group.add_argument("-e", "--encrypt", action="store_true", help="use this for encripting data", default=0)
parser.add_argument("-p", "--path", action="store_true", help="specify a path to a file instead of a string")
parser.add_argument("string", type=str, metavar="String/Path")
parser.add_argument("-o", "--output", metavar="path", type=str, help="specify an output path")
group1 = parser.add_mutually_exclusive_group()
group1.add_argument("--xor", action="store_true", help="uses a XOR encryption method (used by default)")
group1.add_argument("--aes", action="store_true", help="uses an AES encryption method (on going project, can't check password)")
args = parser.parse_args()

#XOR

#check and adjust paths in order to be opened, switching backslash with forwardslash
def retriVer(arg):
    try:    
        if args.path:   #if it's specified a path, start the logic that made it openable      
            lix = list(arg)
            elix = []
            for i in lix:
                if i == "\\":
                    elix.append("/")
                else:
                    elix.append(i)
            path = ''.join(elix)
            file = open(path, "rb")
            y = file.read()
            x = y.strip()              #read content from the file and return it
        else:
            x = arg
    except Exception as e:    #manage exceptions
        print("[*] Wrong path or bad syntax for input, %s." % e)
        sys.exit(0)
    return x




#handles the logic for outputting on a file
def outPutter(arg, data):
    try:    
        lix = list(arg)  #starts the logic for opening paths just like retriVer()
        elix = []
        for i in lix:
            if i == "\\":
                elix.append("/")
            else:
                elix.append(i)
        path = ''.join(elix)
        with open(path, "w+") as file:             #open a file or create it if it doesn't exist, and write in all the data
            file.write("%s" %data)
            file.close
        print("[*] Writing Data to the output file!")
        print("[*] File Saved Successfull at %s." %path)
        
    except Exception as e:            #exception handler
        print("[*] Wrong path or bad syntax for output, %s." % e)
        sys.exit(0)
        


#convert in a bin sequence strings to be encrypted
def binIt(txt):
    b = bin(int(binascii.hexlify(txt), 16)) #convert string into hex by usign binascii module, convert it in an integer, and then into binary
    return b

#convert in string bin sequences 
def strBin(bin):
    n = (int(bin, 2)) 
    w = binascii.unhexlify("%x" %n)
    return w

def checkpass():
    global passwd
    if not passwd:
        print("[*] Empty password try again...")
        passwd = getpass(prompt="[*] Enter a Password : ")
        checkpass()
    else:
        pass
#Main encrypting function
def cryPy(passw, data):
    global magicwrd
    global passwd
    chk = binIt(passwd)
    chk1 = binIt(magicwrd)
    try:    
        a = str((int(passw, 2) ^ int(data, 2)))   #calcolate an header for password check
        b = str((int(chk, 2) ^ int(chk1, 2)))     #encrypt data 
        z = b + a        
    except Exception as e:                        #handle exceptions 
        print(e)
    return z



#Main decrypting function
def decryPy(passw, data):
    global magicwrd                           #set global variables
    global passwd
    chk = binIt(passwd)
    chk1 = binIt(magicwrd)
    try:
        off = len(str((int(chk, 2) ^ int(chk1, 2))))  #calcolate offset usign the password
        pax = bin(int(data[:off]) ^ int(passw, 2))    
        if pax == chk1:                             #check if it match
            b = bin(int(data[off:]) ^ int(passw, 2))  
            a = strBin(b)                             #decrypt  
        else:
            print("[*] Wrong Password Access Denied : Exiting.")    #raise error and sys.exit
            sys.exit(0)
    except Exception as e:
        print("[*] %s, probably whitespace known issue." %e)
    return a




#Varibili Base
stringa = retriVer(args.string)
passwd = getpass(prompt="[*] Enter a Password : ")
AES = args.aes
magicwrd = "magicwrd"
checkpass()

def main():
    global AES
    if AES:
        print("[*] Starting ecnrypting process! Wait!")
        try:
            if args.decrypt:
                if args.output:
                    aes.decrypt(args.string, passwd, args.output)
                else:
                    aes.decrypt(args.string, passwd)  
            else:
                if args.output:
                    aes.encrypt(args.string, passwd, args.output)
                else:
                    aes.encrypt(args.string, passwd)
        except Exception as e:
            print e
        print("[*] File Saved Successfull at %s" %args.output)
    else :
        try:
            if args.decrypt:     #if true start decrypting routine
                x = binIt(passwd)
                print("[*] Starting decrypting process! Wait!")
                if args.output:
                    outPutter(args.output, decryPy(x, stringa)) #if it's specified an output start the routine
                else:
                    print("[*] Printing output to shell.")       #if not specified print the output to the shell                
                    print decryPy(x, stringa)
            else:
                print("[*] Starting encrypting process! Wait!") #if not true start encrypting routine 
                x = binIt(passwd)
                y = binIt(stringa)
                if args.output:
                    outPutter(args.output, cryPy(x, y))
                else:
                    print("[*] Printing output to shell.")
                    print cryPy(x, y)
        except Exception as e:
            print(e)
            print(parser.usage)   #exception print usage


main()
    
    


