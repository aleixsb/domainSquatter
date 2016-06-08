#!/usr/bin/python


import argparse
import os
import sys
import subprocess
import csv
import smtplib
import tempfile
import atexit

urlcrazyPath = '/usr/bin/urlcrazy' # update if your installation differs
dnstwistPath = '/root/Desktop/Python/dnstwist/dnstwist.py' # update if your installation differs

# set up global defaults
tempFiles = [] # define temporary files array

def checkPerms(docRoot, resultsFile):
    # Test if we have execute permissions to docRoot
    if not os.access(docRoot, os.X_OK):
        print "Destination directory " + docRoot + " not accessible."
        print "Please check permissions.  Exiting..."
        sys.exit()
    else:
        pass

    # Test if we have write permissions to docRoot
    try:
        permtest = tempfile.TemporaryFile('w+b', bufsize=-1, dir=docRoot)
    except OSError:
        print "Unable to write to desired directory: " + docRoot + "."
        print "Please check permissions.  Exiting..."
        sys.exit()

def checkDepends(myDomains, knownThreats, docRoot, resultsFile, dtdict, urlcrazy, dnstwist):
    # Test if mydomains.csv exists
    if not os.access(myDomains, os.F_OK) or not os.access(knownThreats, os.F_OK):
        print "Required configuration files - mydomains.csv or knownthreats.csv - not found."
        print "Please verify configuration.  Exiting..."
        sys.exit()
    else:
        pass

    # Test if docRoot is actually a directory
    if not os.path.isdir(docRoot):
        print "Argument: -d " + docRoot + " is not a directory."
        print "Please review arguments.  Exiting..."
        sys.exit()
    else:
        pass

    # Ensure resultsFile isn't actually a directory
    if os.path.exists(resultsFile) and not os.path.isfile(resultsFile):
    #if not os.path.isfile(resultsFile):
        print "Argument: -o " + resultsFile + " should be a regular file but is something else."
        print "Please review arguments.  Exiting..."
        sys.exit()
    else:
        pass
        
    # Test if urlcrazy exists
    if urlcrazy:
        if not os.access(urlcrazyPath, os.F_OK):
            print "URLCrazy specified as " + urlcrazyPath + " but was not found."
            print "Please check urlcrazyPath in crazyParser.py.  Exiting..."
            sys.exit()

    # Test if dnstwist exists
    if dnstwist:
        if not os.access(dnstwistPath, os.F_OK):
            print "DNStwist specified as " + dnstwistPath + "but was not found."
            print "Please check urlcrazyPath in crazyParser.py.  Exiting..."
            sys.exit()

    # Test if dnstwist dictionary exists
    if dtdict:
        if not os.access(dtdict, os.F_OK):
            print "Required dictionary file - dict.csv - not found."
            print "Please verify dict.csv.  Exiting..."
            sys.exit()
        else:
            pass

def doCrazy(docRoot, resultsFile, myDomains, dtdict, urlcrazy, dnstwist):
    # cleanup old results file
    try:
        os.remove(resultsFile)
    except OSError:
        pass
    
    with open(myDomains, 'rbU') as domains:
        reader = csv.reader(domains)
        for domain in domains:
            domain = domain.rstrip()

            # Run urlcrazy if enabled
            if urlcrazy:
                filename = domain + ".uctmp"
                ucoutfile = open(filename, 'w')
                ucargs=[urlcrazyPath, '-f', 'csv', '-o', ucoutfile.name, domain]
                with open(os.devnull, 'w') as devnull:
                    subprocess.call(ucargs, stdout=devnull, close_fds=True, shell=False)
                tempFiles.append(filename)

            # Run dnstwist if enabled
            if dtdict is not None:
                dtargs=[dnstwistPath, '-r', '-c', '-d', dtdict, domain]
            else:
                dtargs=[dnstwistPath, '-r', '-c', domain]
            if dnstwist:
                filename = domain + ".dttmp"
                with open(filename, 'wb') as dtout:
                    output=subprocess.check_output(dtargs, shell=False)
                    dtout.write(output)
                tempFiles.append(filename)

    
def parseOutput(docRoot, knownThreats, myDomains, resultsFile, urlcrazy, dnstwist):

    # Load known threats 
    knownthre = []
    with open(knownThreats, 'rbU') as domfile:
        knownthre = [line.strip() for line in domfile.readlines()]
        knownthre.pop(0)

    # Load domains 
    mydomain = []
    with open(myDomains, 'rbU') as mydomfile:
        mydomain = [line.strip() for line in mydomfile.readlines()]

    # set up domains dictionary
    domains = {}
    for dom in mydomain:
        domains[dom] = list()

    #Parse results from dnstwsit and urlcrazy
    for file in tempFiles:
        #Check if urcrazy is enabled
        if urlcrazy:
            if file.endswith(".uctmp"):
                with open (file, 'rbU') as csvfile:
                    reader = csv.DictReader(row.replace('\0', '') for row in csvfile)
                    for row in reader:
                        if len(row) != 0:
                            if row['CC-A'] != "?":
                                if ((row['Typo'] in knownthre) or (row['Typo'] in mydomain)):
                                    pass
                                else:
                                    #Get name of the active
                                    name = csvfile.name
                                    s = name[:-6]
                                    #Get thread list for that active
                                    l = domains.get(s)
                                    l.append(row['Typo'])
                                    #Update thread list
                                    domains[s] = l

        #Check if urcrazy is enabled
        if dnstwist:
            if file.endswith(".dttmp"):
                with open (file, 'rbU') as csvfile:
                    reader = csv.reader(csvfile)
                    next(reader)
                    for row in reader:
                        if ((row[1] in knownthre) or (row[1] in mydomain)):   
                            pass
                        else:
                            #Get name of the active
                            name = csvfile.name
                            s = name[:-6]
                            #Get thread list for that active
                            l = domains.get(s)
                            l.append(row[1])
                            #Update thread list
                            domains[s] = l

                        
    # dedupe domains list
    for key, value in domains.iteritems():
        lis = dedup(value)
        domains[key] = lis

    
    # write out results
    # this file will only contain the header if there are no new results
    with open(resultsFile, 'wb') as outfile:
        w = csv.writer(outfile)
        for key, value in domains.items():
            w.writerow([key, value])


def doCleanup(docRoot):
    # Delete all temporary .tmp files created by urlcrazy and dnstwist
    for f in tempFiles:
        try:
            os.remove(f)
        except OSError:
            print "Error removing temporary file: " + f
            pass

def dedup(domainslist, idfun=None): # code from http://www.peterbe.com/plog/uniqifiers-benchmark
    if idfun is None:
        def idfun(x): return x
    seen = {}
    result = []
    for item in domainslist:
        marker = idfun(item)
        if marker in seen: continue
        seen[marker] = 1
        result.append(item)
    return result


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(prog='domainSquatter.py', description='domainSquatter - uses urlCrazy and dnsTwist to detect new cyberquatting domains', add_help=True)
    parser.add_argument('-c', '--config', help='Directory location for required config files', default=os.getcwd(), required=False)
    parser.add_argument('-o', '--output', help='Save results to file, defaults to results.csv', default='results.csv', required=False)
    parser.add_argument('-d', '--directory', help='Directory for saving output, defaults to current directory', default=os.getcwd(), required=False)
    parser.add_argument('--dnstwist', help='Use dnstwist for domain discovery, defaults to False', action="store_true", default=False, required=False)
    parser.add_argument('--urlcrazy', help='Use urlcray for domain discovery, defaults to False', action="store_true", default=False, required=False)
    parser.add_argument('--twistdict', help='Load a dictionary to dnsTwist, defaults to False', required=False)

    # Check minimum arguments
    if  len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    if args.config != os.getcwd():
        if os.path.isdir(args.config):
            configDir = args.config
        else:
            print "ERROR! Specified configuration directory " + args.config + " does not exist!"
            print "Exiting..."
            sys.exit()
    else:
        configDir = args.config

    if args.directory != os.getcwd():
        if os.path.isdir(args.directory):
            docRoot = args.directory
        else:
            print "ERROR! Specified output directory " + args.directory + " does not exist!"
            print "Exiting..."
            sys.exit()
    else:
        docRoot = args.directory

    # set up global files
    resultsFile = os.path.join(docRoot, args.output)
    myDomains = os.path.join(configDir,'mydomains.csv')
    knownThreats = os.path.join(configDir,'knownthreats.csv')
    dtdict = None
    if args.twistdict is not None:
        dtdict = os.path.join(configDir, args.twistdict)

    # Check to make sure we have the necessary permissions
    checkPerms(docRoot, resultsFile)

    # Check dependencies
    checkDepends(myDomains, knownThreats, docRoot, resultsFile, dtdict, args.urlcrazy, args.dnstwist)

    # Clean up output files at exit
    atexit.register(doCleanup, docRoot)
    
    # Execute discovery
    doCrazy(docRoot, resultsFile, myDomains, dtdict, args.urlcrazy, args.dnstwist)

    # parse output
    parseOutput(docRoot, knownThreats, myDomains, resultsFile, args.urlcrazy, args.dnstwist)

  

if __name__ == "__main__":
    main()
