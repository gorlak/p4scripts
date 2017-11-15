#
# This script is public domain, with not warranty or guarantee of functionality
# This script was written to minimize server-side load for highly scaled servers
#
# https://github.com/gorlak/p4scripts
#

# core python
import locale
import optparse
import os
import re
import stat
import subprocess
import sys
import time

#
# setup argument parsing
#

parser = optparse.OptionParser()
( options, args ) = parser.parse_args()

import pprint
pp = pprint.PrettyPrinter( indent=4 )

if os.name != "nt":
	print( "Not tested outside of windows\n" )
	exit( 1 )

from ctypes import windll, create_string_buffer

# stdin handle is -10
# stdout handle is -11
# stderr handle is -12

h = windll.kernel32.GetStdHandle(-12)
csbi = create_string_buffer(22)
res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)

if res:
    import struct
    (bufx, bufy, curx, cury, wattr,
     left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
    sizex = right - left + 1
    sizey = bottom - top + 1
else:
    sizex, sizey = 80, 25 # can't determine actual size - return default values


#
# main
#

try:
	increment = 100000
	notify = increment
	count = 0

	matched = 0
	workspaces = dict()
	for arg in args:

		j = open(arg)

		for line in iter(j):
			count = count + 1

			match = re.match( r'@rv@ [0-9]+ @db.have@ @//(.*?)/', line )
			if match != None:
				matched = matched + 1
				workspace = match.group(1)
				workspaceCount = 0
				if workspace in workspaces.keys():
					workspaceCount = workspaces[ workspace ]
				workspaceCount = workspaceCount + 1
				workspaces[ workspace ] = workspaceCount

			if count == notify:
				notify = notify + increment
				print( str( len(workspaces) ) )

				os.system('cls')
				print( "Matched " + str( matched ) + " of " + str( count ) + " lines." )
				
				sortedWorkspaces = list( workspaces.items() )
				sortedWorkspaces.sort(key=lambda tup: tup[1], reverse=True)

				screenLines = 3
				for k, v in sortedWorkspaces:
					print( k + ": " + str( v ) )
					screenLines = screenLines + 1
					if screenLines == sizey:
						break

		j.close()	

except KeyboardInterrupt:
	exit( 1 )
