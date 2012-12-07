# TODO
import threading
import hashlib # ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
import crypt # crypt(3)
import sys # for command-line arguments and file I/O 

class DictionaryAttack(threading.Thread):
    def __init__(self, digest, format, dictionary):
        ''' Constructor - save the password, hash function, and wordlist reference
        '''
        # Call the thread constructor
        threading.Thread.__init__(self)

        # Save the variables
        self.digest = digest
        self.format = format
        self.dictionary = dictionary
        self.cracked = False
        self.password = None

    def get_result(self):
        return self.cracked, self.password

    def compare_password_hashes(self, word):
        ''' Compare the digest of the specified word against the password digest.
        '''
        match = False

        # Determine the hash function type
        # NOTE: this had to be done in local scope to produce the correct hash digest.
        h = hashlib.md5()
        if (self.format == "crypt"):
            pass # defaults to md5
        elif (self.format == "md5"):
            h = hashlib.md5()
        elif (self.format == "sha1"):
            h = hashlib.sha1()
        elif (self.format == "sha256"):
            h = hashlib.sha256()
        elif (self.format == "sha512"):
            h = hashlib.sha512()

        # Perform the computation and comparison
        h.update(word)
        if (h.digest() == self.digest):
            match = True
        return match

    def run(self):
        ''' Attempt to crack the password using the dictionary attack, which
        walks the wordlist in search of a comparable password hash digest.
        
        The supported hash functions are: md5, sha1, sha225, sha256, sha384, sha512, crypt
        '''
        self.cracked = False
        try:
            # Proceed with the attack...
            with open(self.dictionary) as f: 
                for word in f.readlines():

                    # TODO: candidate mangling goes here, if I choose to implement it

                    if (self.compare_password_hashes(word.rstrip('\n'))):
                        self.password = word.rstrip('\n')
                        self.cracked = True
                        return self.cracked # early return to avoid wasted cycles
            if (cracked == False):
                print("Password crack was unsuccessful.")
        except Exception as e:
            print(e)
            raise Exception("Error occurred while cracking password")

        # Return the result...
        return self.cracked