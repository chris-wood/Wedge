# TODO
import threading
import hashlib # ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
import crypt # crypt(3)
import sys # for command-line arguments and file I/O 

class DictionaryAttack(threading.Thread):
    def __init__(self, password, format, dictionary):
        ''' Constructor - save the hash function type and wordlist reference
        '''
        # Call the thread constructor
        threading.Thread.__init__(self)

        # Save the variables
        self.password = password
        self.format = format
        self.dictionary = dictionary

    def compare_password_hashes(self, hashFunction, word):
        ''' Compare the digest of the specified word against the password digest.
        '''
        match = False
        hashFunction.update(word)
        if (hashFunction.digest() == self.password):
            match = True
        return match

    def run(self):
        ''' Attempt to crack the password using the dictionary attack, which
        walks the wordlist in search of a comparable password hash digest.
        
        The supported hash functions are: md5, sha1, sha225, sha256, sha384, sha512, crypt
        '''
        cracked = False

        # Determine the hash function type
        hashFunction = hashlib.md5()
        if (self.format == "crypt"):
            pass # defaults to md5
        elif (self.format == "md5"):
            hashFunction = hashlib.md5()
        elif (self.format == "sha1"):
            hashFunction = hashlib.sha1()
        elif (self.format == "sha256"):
            hashFunction = hashlib.sha256()
        elif (self.format == "sha512"):
            hashFunction = hashlib.sha512()
        else:
            raise Exception("Invalid hash format")

        try:
            # Proceed with the attack...
            with open(self.dictionary) as f: 
                for word in f.readlines():

                    # TODO: candidate mangling goes here, if I choose to implement it

                    if (self.compare_password_hashes(hashFunction, word.rstrip('\n'))):
                        print("Password found: " + word.rstrip('\n'))
                        cracked = True
                        return cracked # early return to avoid wasted cycles
            if (cracked == False):
                print("Password crack was unsuccessful.")
        except:
            raise Exception("Error occurred while cracking password")

        # Return the result...
        return cracked