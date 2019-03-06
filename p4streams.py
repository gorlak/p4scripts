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
parser.add_option( "-d", "--depot", dest="depot", action="store", default=None, help="filter streams to the specified depot" )
parser.add_option( "-l", "--list", dest="list", action="store_true", default=None, help="list client names for each stream" )
parser.add_option( "-f", "--full", dest="full", action="store_true", default=None, help="list full streams only (no virtual)" )
( options, args ) = parser.parse_args()

stream = str ()
if len( args ):
	stream = args[0]

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

	p4Streams = dict ()
	print( "Fetching stream information..." )
	results = p4.run_streams()
	for result in results:
		stream = p4MarshalString( result['Stream'] )
		if not stream.startswith( options.depot if options.depot else "" ):
			continue
		if options.full and "virtual" == p4MarshalString( result['Type'] ):
			continue
		p4Streams[ stream ] = result

	print( "Found %d Streams in Depot %s" % ( len(p4Streams), options.depot if options.depot else "(all depots)" ) )

	p4StreamClients = dict()
	print( "Fetching stream utilization..." )
	for stream in p4Streams:
		result = p4.run_clients( '-S', stream )
		if len( result ):
			streamClients = list()
			for client in result:
				streamClients.append( client )
			p4StreamClients[ stream ] = streamClients

	print( "Found %d Streams used by clients" % len( p4StreamClients ) )

	p4StreamPopularity = sorted( p4StreamClients.items(), key=lambda x: len( x[1] ), reverse=True)
	for key, value in p4StreamPopularity:
		print( "%d: %s" % ( len( value ), key ) )
		if options.list:
			for client in value:
				print( "  %s" % p4MarshalString( client['client'] ) )

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
