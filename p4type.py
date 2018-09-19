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

# bom helper
def get_bom(path):
    with open(path, 'rb') as f:
        raw = f.read(4) # will read less if the file is smaller
    for enc,boms in \
            ('utf8',(codecs.BOM_UTF8,)),\
            ('utf16',(codecs.BOM_UTF16_LE,codecs.BOM_UTF16_BE)),\
            ('utf32',(codecs.BOM_UTF32_LE,codecs.BOM_UTF32_BE)):
        if any(raw.startswith(bom) for bom in boms): return enc
    return None

#
# setup argument parsing
#

parser = optparse.OptionParser()
parser.add_option( "-e", "--exact", dest="select_exact", action="store", default=None, help="list the depot path of the files that match the specified fully-qualified type (including attributes and storage)" )
parser.add_option( "-b", "--base", dest="select_base", action="store", default=None, help="list the depot path of the files whose base type match the specified base type (not including attributes and storage)" )
parser.add_option( "-8", "--utf8", dest="select_utf8", action="store_true", default=None, help="only include files that have utf8 byte order marks" )
parser.add_option( "-6", "--utf16", dest="select_utf16", action="store_true", default=None, help="only include files that have utf16 byte order marks" )
parser.add_option( "-3", "--utf32", dest="select_utf32", action="store_true", default=None, help="only include files that have utf32 byte order marks" )
parser.add_option( "-E", "--set-exact", dest="set_exact", action="store", default=None, help="set the new file type" )
parser.add_option( "-B", "--set-base", dest="set_base", action="store", default=None, help="change the base file type, but preserve attributes and storage" )
( options, args ) = parser.parse_args()

extension = str ()
if len( args ):
	extension = '.' + args[0]

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

	# setup client
	client = p4.fetch_client()
	clientRoot = client[ 'Root' ]
	if ( clientRoot[-1] != '\\' ) and ( clientRoot[-1] != '/' ):
		clientRoot += '/'

	clientMap = P4.Map( client[ 'View' ] )
	clientSlashesFixed = re.sub( r'\\', r'\\\\', clientRoot )
	def p4MakeLocalPath( f ):
		f = clientMap.translate( f )
		exp = '//' + re.escape( client[ 'Client' ] ) + '/(.*)'
		f = re.sub( exp, clientSlashesFixed + '\\1', f, 0, re.IGNORECASE )
		f = re.sub( r'/', r'\\', f )
		f = re.sub( r'%40', '@', f ) # special handling due to p4 character
		f = re.sub( r'%23', '#', f ) # special handling due to p4 character
		f = re.sub( r'%2A', '*', f ) # special handling due to p4 character
		f = re.sub( r'%25', '%', f ) # special handling due to p4 character
		return f

	#
	# query lots of info
	#

	p4Types = dict ()
	print( "Fetching file information..." )
	results = p4.run_fstat('-Os', '-F', '^action=delete & ^headAction=delete & ^headAction=move/delete', '...' + extension)
	for result in results:
		f = result[ 'depotFile' ]
		f = p4MarshalString( f )
		t = None
		if 'type' in result:
			t = result[ 'type' ]
		elif 'headType' in result:
			t = result[ 'headType' ]
		else:
			print( 'Couldn\'t find type for ' + f + ', got ' + str( result ) )
			continue
		t = p4MarshalString( t )
		if not t in p4Types:
			p4Types[ t ] = list ()
		p4Types[ t ].append( f )

	#
	# select the list of files we care about
	#

	files = list ()

	def shouldSkipBecauseBom( f ):
		if options.select_utf8:
			if "utf8" != get_bom( p4MakeLocalPath( f ) ):
				return True
		elif options.select_utf16:
			if "utf16" != get_bom( p4MakeLocalPath( f ) ):
				return True
		elif options.select_utf32:
			if "utf32" != get_bom( p4MakeLocalPath( f ) ):
				return True
		return False

	if options.select_exact:
		if options.select_exact in p4Types:
			for f in sorted( p4Types[ options.select_exact ] ):
				if not shouldSkipBecauseBom( f ):
					files.append( ( f, options.select_exact ) )

	if options.select_base:
		for k, v in p4Types.items():
			if k.startswith( options.select_base ):
				for f in v:
					if not shouldSkipBecauseBom( f ):
						files.append( ( f, k ) )

	#
	# make changes, if desired. list selection otherwise
	#

	# symlink omitted because it's different
	validBaseTypes = [ 'text', 'binary', 'apple', 'resource', 'unicode', 'utf8', 'utf16' ]

	if options.set_exact:

		print( "Setting type to " + options.set_exact + "...")

		for f in sorted( files ):
			print( f[0] )
			p4.run_edit('-t', options.set_exact, f[0])

	elif options.set_base:
		
		if options.set_base not in validBaseTypes:
			print( "Desired base type " + options.set_base + " is not a recognized base type")
			os.exit( 1 )
		
		print( "Changing base type to " + options.set_base + "...")

		for f in sorted( files ):

			# determine the current base filetype
			base = None
			for b in validBaseTypes:
				if f[1].startswith( b ):
					base = b
					break

			if not base:
				print( "Existing type " + f[1] + " has unrecognized base type" )
				os.exit( 1 )

			# transplant flags onto the new base filetype
			newBase = f[1].replace( base, options.set_base )

			print( f[0] )
			opened = p4.run_opened( f[0] )
			if len( opened ) and 'change' in opened[0]:
				p4.run_reopen( '-t', newBase, f[0] )
			else:
				p4.run_edit( '-t', newBase, f[0] )

	else:
		print( "Total Type breakdown:" )
		for k, v in sorted( p4Types.items() ):
			print( " got " + str( len( v ) ) + " files of type " + k )

		if len( files ):
			print( "Files:" )
			for f in sorted( files ):
				print( f[0] )

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
