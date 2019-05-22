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
parser.add_option( "-d", "--depot",  dest="depot",  action="store",      default=None, help="filter streams to the specified depot" )
parser.add_option( "-s", "--stream", dest="stream", action="store",      default=None, help="filter streams to the specified depot" )
parser.add_option( "-l", "--list",   dest="list",   action="store_true", default=None, help="list client names for each stream" )
parser.add_option( "-f", "--full",   dest="full",   action="store_true", default=None, help="list full streams only (no virtual)" )
( options, args ) = parser.parse_args()

#stream = str ()
#if len( args ):
#p4	stream = args[0]

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
