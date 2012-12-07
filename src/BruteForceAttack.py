# TODO
import threading
import hashlib

class BruteForceAttack(threading.Thread):
    def __init__(self, password, format, charSet, incrementIndex):
        ''' Constructor - save the hash function type and wordlist reference
        '''
        # Call the thread constructor
        threading.Thread.__init__(self)

        # Save the variables
        self.format = format
        self.charSet = charSet
        self.incrementIndex = incrementIndex
        self.password = password

        # Determine the hash function type
        self.h = hashlib.md5()
        if (format == "crypt"):
            pass # defaults to md5
        elif (format == "md5"):
            self.h = hashlib.md5()
        elif (format == "sha1"):
            self.h = hashlib.sha1()
        elif (format == "sha256"):
            self.h = hashlib.sha256()
        elif (format == "sha512"):
            self.h = hashlib.sha512()
        else:
            raise Exception("Invalid hash format")

    def generate_digest(self, hashFunction, plaintext):
        ''' Generate the hash digest of the given plaintext using the specified hash function.
        ''' 
        hashFunction.update(plaintext)
        return hashFunction.digest()

    def compare_password_hashes(self, word):
        ''' Compare the digest of the specified word against the password digest.
        '''
        match = False
        if (self.generate_digest(self.h, word) == self.password):
            match = True
        return match

    def run(self):
        ''' Attempt to crack the password using the dictionary attack, which
        walks the wordlist in search of a comparable password hash digest.
        
        The supported hash functions are: md5, sha1, sha225, sha256, sha384, sha512, crypt
        '''
        cracked = False
        try:
            with open(self.dictionary) as f: 
                for word in f.readlines():

                    # TODO: candidate mangling goes here

                    if (self.compare_password_hashes(word.rstrip('\n'))):
                        print("Password found: " + word.rstrip('\n'))
                        cracked = True
                        return cracked
            if (cracked == False):
                print("Password crack was unsuccessful.")
        except:
            raise Exception("Error occurred while cracking password")

        # Return the result...
        return cracked