#
# This script is public domain, with not warranty or guarantee of functionality
# This script was written to minimize server-side load for highly scaled servers
#
# https://github.com/gorlak/p4scripts
#

# core python
import codecs
import locale
import optparse
import os
import re

# p4api
import P4

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
	encoding = 'UTF-8'
	if not p4.server_unicode:
		encoding = locale.getpreferredencoding()
		if hasattr(p4, 'encoding'):
			p4.encoding = 'raw'

	def p4MarshalString( data ):
		if isinstance( data, str ):
			return data
		elif isinstance( data, bytes ):
			return data.decode( encoding )
		else:
			print( 'Unexpected type: ' + data )
			exit( 1 )

	#
	# capture server list
	#

	servers = p4.run_servers()

	for server in servers:
		port = p4MarshalString( server['Address'] )
		if len( port ):
			print( port )

except P4.P4Exception:
	print( traceback.format_exc() )
	print( "\nP4 'info':" )
	pp.pprint( info )
	print( "\nEnvironment:" )
	pp.pprint( dict(os.environ) )
	exit( 1 )

except KeyboardInterrupt:
	exit( 1 )
