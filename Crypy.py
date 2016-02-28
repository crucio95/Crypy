import binascii
import argparse
import sys

#Display the banner
with open("banner.txt") as f:
    print(f.read())


#Parser for the arguments
parser = argparse.ArgumentParser(description="Simple Python's script for Encrypting and Decrypting Data", epilog="And That's All! Start Encrypting!")
parser.add_argument("string", type=str, metavar="String/Path")
parser.add_argument("password", type=str, metavar="Password")
parser.add_argument("-p", "--path", action="store_true", help="specify a path to a file instead of a string")
parser.add_argument("-o", "--output", metavar="path", type=str, help="specify an output path")
group = parser.add_mutually_exclusive_group()
group.add_argument("-d", "--decrypt", action="store_true", help="use this for decripting data", default=0)
group.add_argument("-e", "--encrypt", action="store_true", help="use this for encripting data", default=0)
args = parser.parse_args()

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
            file = open(path)
            x = file.read()    #read content from the file and return it
        else:
            x = arg
    except Exception as e:    #manage exceptions
        print("[*] Wrong path or bad syntax for input, %s" % e)
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
        print("[*] File Saved Successfull at %s" %path)
        
    except Exception as e:            #exception handler
        print("[*] Wrong path or bad syntax for output, %s" % e)
        sys.exit(0)
        


#convert in a bin sequence strings to be encrypted
def binIt(txt):
    b = bin(int(binascii.hexlify(txt), 16)) #convert string into hex by usign binascii module, convert it in an integer, and then into binary
    return b




#convert in string bin sequences 
def strBin(bin):
    n = int(bin, 2)       #convert binary data in integer, and then unhexlify it
    w = binascii.unhexlify('%x' %n)
    return w



#Varibili Base
stringa = retriVer(args.string)
passwd = args.password

#Variables for handle the logic of checking the password
magicwrd = "magicwrd"
chk = binIt(passwd)
chk1 = binIt(magicwrd)

#Main encrypting function
def cryPy(passw, data):
    global chk         #set global variables
    global chk1
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
    global chk
    global chk1
    off = len(str((int(chk, 2) ^ int(chk1, 2))))  #calcolate offset usign the password
    pax = bin(int(data[:off]) ^ int(passw, 2))    
    x = strBin(pax)
    if x == magicwrd:                             #check if it match
        b = bin(int(data[off:]) ^ int(passw, 2))  
        a = strBin(b)                             #decrypt  
    else :
        print("[*] Wrong Password Access Denied : Exiting")    #raise error and sys.exit
        sys.exit(0)
    return a



def main():
       
    try:
        if args.decrypt:     #if true start decrypting routine
            x = binIt(passwd)
            print("[*] Starting decrypting process! Wait!")
            if args.output:
                outPutter(args.output, decryPy(x, stringa)) #if it's specified an output start the routine
            else:
                print("[*] Printing output to shell")       #if not specified print the output to the shell                
                print decryPy(x, stringa)
        else:
            print("[*] Starting encrypting process! Wait!") #if not true start encrypting routine 
            x = binIt(passwd)
            y = binIt(stringa)
            if args.output:
                outPutter(args.output, cryPy(x, y))
            else:
                print("[*] Printing output to shell")
                print cryPy(x, y)
    except:
        print(parser.usage)   #exception print usage


main()
    
    


