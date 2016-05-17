import binascii
from getpass import getpass
import sys

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
        



def binIt(txt):
    b = bin(int(binascii.hexlify(txt), 16)) #convert string into hex by usign binascii module, convert it in an integer, and then into binary
    return b


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

def cryPy(passw, data, magicwrd):
    chk1 = binIt(magicwrd)
    try:    
        a = str((int(passw, 2) ^ int(data, 2)))   #calcolate an header for password check
        b = str((int(passw, 2) ^ int(chk1, 2)))     #encrypt data 
        z = b + a        
    except Exception as e:                        #handle exceptions 
        print(e)
    return z




def decryPy(passw, data, magicwrd):
    chk1 = binIt(magicwrd)
    try:
        off = len(str((int(passw, 2) ^ int(chk1, 2))))  #calcolate offset usign the password
        pax = strBin(bin(int(data[:off]) ^ int(passw, 2)))    
        if pax == magicwrd:                             #check if it match
            b = bin(int(data[off:]) ^ int(passw, 2))  
            a = strBin(b)                             #decrypt  
        else:
            print("[*] Wrong Password Access Denied : Exiting.")    #raise error and sys.exit
            sys.exit(0)
    except Exception as e:
        print("[*] %s, probably whitespace known issue." %e)
    return a