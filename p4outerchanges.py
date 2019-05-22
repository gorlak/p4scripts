#
# This script is public domain, with not warranty or guarantee of functionality
# This script was written to minimize server-side load for highly scaled servers
#
# https://github.com/gorlak/p4scripts
#

# core python
import codecs
import locale
import math
import optparse
import os
import re

# p4api
import P4

#
# setup argument parsing
#

parser = optparse.OptionParser()
parser.add_option( "-v", "--verbose", dest="verbose", action="store_true", default=False, help="verbose output" )
( options, args ) = parser.parse_args()

if not len( args ) > 1:
	print("Please specify two views to report changes fully integrated: from, to")
	exit( 1 )

fromView = args[0]
toView = args[1]

import pprint
pp = pprint.PrettyPrinter( indent=4 )

if os.name != "nt":
	print( "Not tested outside of windows\n" )
	exit( 1 )

#
# main
#

try:

	#
	# connect and setup p4
	#

	# perl sets this differently from os.getcwd() (%CD% on windows), and p4api reads it
	os.putenv( 'PWD', os.getcwd() )

	p4 = P4.P4()
	p4.connect()
	p4.exception_level = 1 # omit warnings
	info = p4.run_info()

	# handle non-unicode servers by marshalling raw bytes to local encoding
	if not p4.server_unicode:
		p4.encoding = 'raw'

	def p4MarshalString( data ):
		if isinstance( data, str ):
			return data
		elif isinstance( data, bytes ):
			return data.decode( locale.getpreferredencoding() )
		else:
			print( 'Unexpected type: ' + data )
			os.exit( 1 )

	#
	# query lots of info
	#

	print("Fetching history of " + fromView)
	changes = p4.run_changes( fromView )

	lastIntegrated = None
	if len(changes):
		print("Checking " + str( len( changes ) ) + " changes for the last fully integrated change...")

		change = 0
		while change < len(changes):
			cl = p4MarshalString( changes[change]['change'] )

			print( "Checking interchanges of " + cl )
			result = p4.run_interchanges( '-n', fromView + '@' + cl + ',' + cl, toView )
			if len( result ):
				change = change + 1
			else:
				print( "Change %s has been integrated" % cl )
				break
		
	#
	# disconnect
	#

	p4.disconnect()

except P4.P4Exception:
	print( traceback.format_exc() )
	print( "\nP4 'info':" )
	pp.pprint( info )
	print( "\nEnvironment:" )
	pp.pprint( dict(os.environ) )
	exit( 1 )

except KeyboardInterrupt:
	exit( 1 )
