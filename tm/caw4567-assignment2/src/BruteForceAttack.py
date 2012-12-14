################################################################
#
# File: BruteForceAttack.py
# Author: Christopher A. Wood, caw4567@rit.edu
# Version: 12/8/12
#
################################################################

import threading
import time # for time limit on the attack
import hashlib # ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
import crypt # crypt(3)
import sys # for command-line arguments and file I/O 

class BruteForceAttack(threading.Thread):
    ''' This thread is responsible for running a brute force attack 
    to crack an encrypted password. 
    '''
    def __init__(self, digest, format, characterSet, increment):
        ''' Constructor - save the password, hash function, and wordlist reference
        '''
        # Call the thread constructor
        threading.Thread.__init__(self)

        # Save the variables
        self.digest = digest
        self.format = format
        self.characterSet = characterSet
        assert(len(self.characterSet) > 0) # can't be empty
        self.increment = increment
        assert(self.increment < len(self.characterSet)) # can't increment farther than the set
        self.cracked = False
        self.password = None
        self.startTime = 0
        self.maxTime = 500000 # make this much larger when running the actual tests

    def get_result(self):
        ''' Retrieve the result from running this attack
        '''
        return self.cracked, self.password

    def compare_password_hashes(self, word):
        ''' Compare the digest of the specified word against the password digest.
        '''
        match = False

        # Determine the hash function type
        # NOTE: this had to be done in local scope to produce the correct hash digest.
        h = hashlib.md5()
        if (self.format == "crypt"):
            pass # defaults to md5 because we aren't handling salted passwords yet
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

    def checkCandidates(self, numToAdd = 0, baseString = ""):
        ''' Recursively build up the candidate strings to check.
        '''
        if (numToAdd == 0):
            return self.walkCharacterSet(baseString = baseString)
        else:
            cracked = False
            for c in self.characterSet:
                candidate = baseString + c
                if (self.checkCandidates(numToAdd - 1, candidate) == True):
                    cracked = True
                    return cracked
            return cracked

    def walkCharacterSet(self, baseString = ""):
        ''' Walk the character set to do the brute force attack.
        '''
        # Check to see if we've gone over the time limit (the main terminating condition)
        if ((time.time() - self.startTime) > self.maxTime):
            return False

        # Walk the character set...
        position = 0
        while (position < len(self.characterSet)):
            candidate = baseString + self.characterSet[position]
            if (self.compare_password_hashes(candidate.rstrip('\n'))):
                self.password = candidate.rstrip('\n')
                self.cracked = True
                return self.cracked # early return to avoid wasted cycles
            position = position + self.increment
        return False

    def run(self):
        ''' Attempt to crack the password using the dictionary attack, which
        walks the wordlist in search of a comparable password hash digest.
        
        The supported hash functions are: md5, sha1, sha225, sha256, sha384, sha512, crypt
        '''
        self.cracked = False
        try:
            self.startTime = time.time()
            length = 0

            # Continue until we run out of time, checking all possible combinations with the given character set
            while ((time.time() - self.startTime) < self.maxTime):
                self.cracked = self.checkCandidates(length)
                if (self.cracked == True):
                    return self.cracked
                length = length + 1
        except Exception as e:
            print(e)
            raise Exception("Error occurred while cracking password")

        # Return the result...
        return self.cracked