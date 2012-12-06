# TODO
import threading

class DictionaryAttack(threading.Thread):

# TODO: make these class methods and then update the Wedge.py file to make it work

def generateHash(password, format):
    ''' TODO

    ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
    '''

    digest = ""

    if (format == "crypt"):
        pass
    elif (format == "md5"):
        h = hashlib.md5()
        h.update(password)
        digest = h.digest()
    elif (format == "sha1"):
        h = hashlib.sha1()
        h.update(password)
        digest = h.digest()
    elif (format == "sha256"):
        h = hashlib.sha256()
        h.update(password)
        digest = h.digest()
    elif (format == "sha512"):
        h = hashlib.sha512()
        h.update(password)
        digest = h.digest()
    else:
        raise Exception("Invalid hash format")

    return digest

def compare_password_hashes(word, password, format):
    ''' TODO
    '''

    match = False

    if (format == "crypt"):
        pass
    elif (format == "md5"):
        h = hashlib.md5()
        h.update(word)
        if (h.digest() == password):
            match = True
    elif (format == "sha1"):
        h = hashlib.sha1()
        h.update(word)
        if (h.digest() == password):
            match = True
    elif (format == "sha256"):
        h = hashlib.sha256()
        h.update(word)
        if (h.digest() == password):
            match = True
    elif (format == "sha512"):
        h = hashlib.sha512()
        h.update(word)
        if (h.digest() == password):
            match = True
    else:
        raise Exception("Invalid hash format")

    return match

def crack_password(format, password):
    ''' TODO

    ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
    '''
    global DICTIONARY
    cracked = False
    try:
        with open(DICTIONARY) as f: 
            for word in f.readlines():

                # TODO: candidate mangling goes here

                if (compare_password_hashes(word.rstrip('\n'), password, format)):
                    print("Password found: " + word.rstrip('\n'))
                    cracked = True
                    return cracked
        if (cracked == False):
            print("Password crack was unsuccessful.")
                
    except:
        raise Exception("Error occurred while cracking password")