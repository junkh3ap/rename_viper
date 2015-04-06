#!/usr/bin/python

import sqlite3 as lite
import sys
import re
import subprocess
import time

# wait time between sets of 4 calls for VirusTotal
DELAY = 60
# path to viper sqlite location
VIPERDB = "/root/Documents/infosec/malware/viper/viper.db" 
# minimum number of character to constitute a new file name
MINCHARS = 3
# Is vtTool using a Public VirusTotal key (and is therefore throttled)?
ISPUBKEY = True

# define regexp function use in sqlite query
def regexp(expr, item):
    reg = re.compile(expr)
    return reg.search(item) is not None

con = None

try:
    con = lite.connect(VIPERDB)
    # create sqlite function
    con.create_function("REGEXP", 2, regexp)

    cur = con.cursor()
    # this regex pulls only those filenames that are md5 hashes
    cur.execute("select name from malware where name REGEXP '[0-9a-hA-H]{32}'")

    rows = cur.fetchall()
    i = 1
    for row in rows:
        hashname = "%s" % row
        print "Processing %s through vtTool..." % hashname
        # pass hash through to VirusTotal via vtTool.py
        output = subprocess.check_output(['vtTool.py', '-hash', hashname]).splitlines(True)
        # Go through the rows and update the name in the database
        # if the most common word is > MINCHARS long
        for line in output:
            if "Most frequent word: " in line:
                end = line.index(" ", 20)
                newname = line[20:end]
                if len(newname) > MINCHARS:
                    cur.execute("update malware set name = '{0}' where name = '{1}';".format(newname, hashname))
        # If using a free public key, VirusTotal only allows 4 requests per minute
        # so let's wait every 4 calls
        if not int(i % 4) and ISPUBKEY:
            print "Delaying for 60 seconds because of VT request throttling"
            time.sleep(DELAY)
        i += 1
    con.commit()
except lite.Error, e:
    print "%s" % e.args[0]
finally:
    if con:
        con.close()
