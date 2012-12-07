################################################################
#
# File: wedge.py
# Author: Christopher A. Wood, caw4567@rit.edu
# Version: 12/4/12
#
################################################################

# Used libraries
import hashlib # ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
import crypt # crypt(3)
import sys # for command-line arguments and file I/O 
import DictionaryAttack

#easyRange = [32,33,36,42,43] + range(48, 58) + range(65, 91) + range(97, 123)
#allRange = range(32,127)
#hash = "<16 hex pairs here>"
#salt = "<salt>"

# Wedge parameters
hashFile = ""
targetUser = ""
hashFormat = "md5"

# The hard-coded dictionary (that can be changed)
dictionary = "cain.txt"

#def checkPassword(password):
#    m = md5.new(password)
#    m = md5.new(m.hexdigest() + salt)
#    if (m.hexdigest() == hash):
#        print "match [" + password + "]"
#        sys.exit()

#def recurse(width, position, baseString):
    # current position
    #for char in easyRange:
    #    if (position < width - 1):
    #        recurse(width, position + 1, baseString + "%c" % char)
    #    checkPassword(baseString + "%c" % char)

def print_banner():
    ''' Simply print the banner for Wedge.
    '''
    print("Wedge - password cracker by Christopher A. Wood (caw4567@cs.rit.edu)")
    print("Version: 0.1, 12/4/12")
    print("Homepage: www.christopher-wood.com")
    print("")

def print_usage():
    ''' Simply print the usage message for Wedge.
    '''
    print("Usage: python wedge.py file [OPTIONS]")
    print("  -h=FILE - the password hash file")
    print("  -f=FORMAT - the format to use for obfuscation (crypt/md5 supported)")
    print("  -u=USER - the user to target in the password file")
    #print("  -d=DICT - the wordlist/dictionary to use in the dictionary attack")

def print_params():
    ''' TODO
    '''
    global hashFile
    global targetUser
    global hashFormat
    global dictionary
    print("Wedge parameters:")
    print("  hash file = " + str(hashFile))
    print("  user = " + str(targetUser))
    print("  format = " + str(hashFormat))
    print("  dictionary = " + str(dictionary))

#TODO: split into print_banner and print_usage...

def parse_commandline_string(param):
    ''' TODO
    '''
    global hashFile
    global hashFormat
    global targetUser
    if ("-h=" in param):
        hashFile = param[3:]
    elif ("-f=" in param):
        hashFormat = param[3:]
    elif ("-u=" in param):
        targetUser = param[3:]
    else:
        raise Exception("Invalid command-line option: " + str(param))

def read_password():
    ''' TODO
    '''
    print("")
    password = raw_input("Enter a password: ")
    return password

def main():
    ''' The main method to parse command-line arguments and start the password cracking logic
    '''
    args = sys.argv
    global hashFile
    global hashFormat
    global targetUser
    global dictionary

    # Banner...
    print_banner()

    try:
        # Check the command-line arguments
        print("################################")
        print("Checking command line arguments.")
        if (len(args) == 2):
            parse_commandline_string(args[1])
        elif (len(args) == 3):
            parse_commandline_string(args[1])
            parse_commandline_string(args[2])
        elif (len(args) == 4):
            parse_commandline_string(args[1])
            parse_commandline_string(args[2])
            parse_commandline_string(args[3])
        elif (len(args) > 4):
            raise Exception("Invalid number of command-line parameters")

        # Determine the hash function to use
        h = hashlib.md5()
        if (hashFormat == "crypt"):
            pass # defaults to md5
        elif (hashFormat == "md5"):
            h = hashlib.md5()
        elif (hashFormat == "sha1"):
            h = hashlib.sha1()
        elif (hashFormat == "sha256"):
            h = hashlib.sha256()
        elif (hashFormat == "sha512"):
            h = hashlib.sha512()

        # Display the cracking options
        print_params()
        print("################################")
        try:
            if (len(hashFile) > 0):
                with open(hashFile) as f: 
                    pass
                    # TODO: read from the file and then execute the crack_password for each line
            else:
                password = read_password()
                h.update(password)
                digest = h.digest()
                print("Hashed password") 
                print(digest)
                
                # Start the attack thread
                print("Spawning the attack thread...")
                attack = DictionaryAttack.DictionaryAttack(digest, hashFormat, dictionary)
                print("asd")
                attack.start()

                #crack_password(hashFormat, digest)
        except IOError as e:
            raise Exception("File (" + str(hashFile) + ") as does not exist.")

    except Exception as e:
        print("ERROR: " + str(e))
        print("################################")
        print_usage()


# Wedge our way in...
if (__name__ == '__main__'):
    main()
    '''
    print "Target Hash [" + hash + "] Salt [" + salt + "]"
    maxChars = 13
    for baseWidth in range(1, maxChars + 1):
        print "checking passwords width [" + `baseWidth` + "]"
        recurse(baseWidth, 0, "")
    '''