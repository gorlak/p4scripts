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
import traceback

# p4api
import P4

#
# setup argument parsing
#

parser = optparse.OptionParser()
parser.add_option( "-x", "--exit", dest="exit", action="store_true", default=False, help="set exit code for clean/dirty status of shown info" )
parser.add_option( "-q", "--quiet", dest="quiet", action="store_true", default=False, help="dont display status report of files" )
parser.add_option( "-p", "--progress", dest="progress", action="store_true", default=False, help="display progress for large operations" )
parser.add_option( "-s", "--show_all", dest="show_all", action="store_true", default=False, help="show differences between the local workspace and the server workspace" )
parser.add_option( "--sa", "--show_added", dest="show_added", action="store_true", default=False, help="show: files that are opened for add" )
parser.add_option( "--se", "--show_edited", dest="show_edited", action="store_true", default=False, help="show: files that are opened for edit" )
parser.add_option( "--sm", "--show_missing", dest="show_missing", action="store_true", default=False, help="show: files that are missing locally" )
parser.add_option( "--sx", "--show_extra", dest="show_extra", action="store_true", default=False, help="show: files that are unknown or deleted at #have" )
parser.add_option( "--sf", "--show_attrs", dest="show_attrs", action="store_true", default=False, help="show: files with incorrect attributes" )
parser.add_option( "-c", "--clean_all", dest="clean_all", action="store_true", default=False, help="clean local workspace to match the server workspace" )
parser.add_option( "--ca", "--clean_added", dest="clean_added", action="store_true", default=False, help="clean: delete and revert files that are opened for add" )
parser.add_option( "--ce", "--clean_edited", dest="clean_edited", action="store_true", default=False, help="clean: revert files that are opened for edit" )
parser.add_option( "--cm", "--clean_missing", dest="clean_missing", action="store_true", default=False, help="clean: restore files that are missing locally" )
parser.add_option( "--cx", "--clean_extra", dest="clean_extra", action="store_true", default=False, help="clean: delete files that are unknown or deleted at #have" )
parser.add_option( "--cd", "--clean_empty", dest="clean_empty", action="store_true", default=False, help="clean: delete empty directories" )
parser.add_option( "--cf", "--clean_attrs", dest="clean_attrs", action="store_true", default=False, help="clean: repair any incorrect file attributes" )
parser.add_option( "-v", "--verify", dest="verify", action="store_true", default=False, help="verify integrity of existing files")
parser.add_option( "-r", "--repair", dest="repair", action="store_true", default=False, help="repair files that fail verification")
parser.add_option( "-R", "--reset", dest="reset", action="store_true", default=False, help="completely reset everything")
( options, args ) = parser.parse_args()

if options.repair:
	options.verify = True

if options.reset:
	options.verify = True
	options.repair = True
	options.clean_all = True

if options.show_all:
	options.show_added = True
	options.show_edited = True
	options.show_missing = True
	options.show_extra = True
	options.show_attrs = True

if options.clean_all:
	options.clean_added = True
	options.clean_edited = True
	options.clean_missing = True
	options.clean_extra = True
	options.clean_empty = True
	options.clean_attrs = True

import pprint
pp = pprint.PrettyPrinter( indent=4 )

if os.name != "nt":
	print( "Not tested outside of windows\n" )
	exit( 1 )

#
# win32 for junction identification/resolution
#  https://eklausmeier.wordpress.com/2015/10/27/working-with-windows-junctions-in-python/
#

from ctypes import *
from ctypes.wintypes import *

kernel32 = WinDLL('kernel32')
LPDWORD = POINTER(DWORD)
UCHAR = c_ubyte
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_READONLY = 0x00001
FILE_ATTRIBUTE_REPARSE_POINT = 0x00400
INVALID_HANDLE_VALUE = HANDLE(-1).value
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FSCTL_GET_REPARSE_POINT = 0x000900A8
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C
MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 0x4000

GetFileAttributesW = kernel32.GetFileAttributesW
GetFileAttributesW.restype = DWORD
GetFileAttributesW.argtypes = (LPCWSTR,)

CreateFileW = kernel32.CreateFileW
CreateFileW.restype = HANDLE
CreateFileW.argtypes = (LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE)

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = (HANDLE,)

DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.restype = BOOL
DeviceIoControl.argtypes = (HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPVOID)

class GENERIC_REPARSE_BUFFER(Structure):
	_fields_ = (('DataBuffer', UCHAR * 1),)

class SYMBOLIC_LINK_REPARSE_BUFFER(Structure):
	_fields_ = (('SubstituteNameOffset', USHORT), ('SubstituteNameLength', USHORT), ('PrintNameOffset', USHORT), ('PrintNameLength', USHORT), ('Flags', ULONG), ('PathBuffer', WCHAR * 1))
	@property
	def PrintName(self):
		arrayt = WCHAR * (self.PrintNameLength // 2)
		offset = type(self).PathBuffer.offset + self.PrintNameOffset
		return arrayt.from_address(addressof(self) + offset).value

class MOUNT_POINT_REPARSE_BUFFER(Structure):
	_fields_ = (('SubstituteNameOffset', USHORT), ('SubstituteNameLength', USHORT), ('PrintNameOffset', USHORT), ('PrintNameLength', USHORT), ('PathBuffer', WCHAR * 1))
	@property
	def PrintName(self):
		arrayt = WCHAR * (self.PrintNameLength // 2)
		offset = type(self).PathBuffer.offset + self.PrintNameOffset
		return arrayt.from_address(addressof(self) + offset).value

class REPARSE_DATA_BUFFER(Structure):
	class REPARSE_BUFFER(Union):
		_fields_ = (('SymbolicLinkReparseBuffer', SYMBOLIC_LINK_REPARSE_BUFFER), ('MountPointReparseBuffer', MOUNT_POINT_REPARSE_BUFFER), ('GenericReparseBuffer', GENERIC_REPARSE_BUFFER))
	_fields_ = (('ReparseTag', ULONG), ('ReparseDataLength', USHORT), ('Reserved', USHORT), ('ReparseBuffer', REPARSE_BUFFER))
	_anonymous_ = ('ReparseBuffer',)

def isjunction(path):
	result = GetFileAttributesW(path)
	if result == INVALID_FILE_ATTRIBUTES:
		raise WinError()
	return bool(result & FILE_ATTRIBUTE_REPARSE_POINT)

def readjunction(path):
	reparse_point_handle = CreateFileW(path, 0, 0, None, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, None)
	if reparse_point_handle == INVALID_HANDLE_VALUE:
		raise WinError()
	target_buffer = c_buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	n_bytes_returned = DWORD()
	io_result = DeviceIoControl(reparse_point_handle, FSCTL_GET_REPARSE_POINT, None, 0, target_buffer, len(target_buffer), byref(n_bytes_returned), None)
	CloseHandle(reparse_point_handle)
	if not io_result:
		raise WinError()
	rdb = REPARSE_DATA_BUFFER.from_buffer(target_buffer)
	if rdb.ReparseTag == IO_REPARSE_TAG_SYMLINK:
		return rdb.SymbolicLinkReparseBuffer.PrintName
	elif rdb.ReparseTag == IO_REPARSE_TAG_MOUNT_POINT:
		return rdb.MountPointReparseBuffer.PrintName
	raise ValueError("not a link")

#
# main
#

def dbg(str):
	#print(str)
	pass

try:

	#
	# connect and setup p4
	#

	# perl sets this differently from os.getcwd() (%CD% on windows), and p4api reads it
	os.putenv( 'PWD', os.getcwd() )

	p4 = P4.P4()
	p4.exception_level = 1 # omit warnings
	p4.connect()
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

	# handle the p4config file special as its always hanging out, if it exists
	p4configFile = p4.p4config_file
	if p4configFile != None:
		p4configFile = p4configFile.lower()[ len( os.getcwd() ) + 1 :]

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

	depotMap = clientMap.reverse()
	def p4MakeDepotPath( f, revRange = "" ):
		exp = re.escape( clientRoot[:-1] ) + r'\\(.*)'
		f = re.sub( exp, '//' + client[ 'Client' ] + '/\\1', f, 0, re.IGNORECASE )
		f = re.sub( r'\\', '/', f )
		f = re.sub( r'\%', '%25', f ) # special handling due to p4 character
		f = re.sub( r'\*', '%2A', f ) # special handling due to p4 character
		f = re.sub( r'\#', '%23', f ) # special handling due to p4 character
		f = re.sub( r'\@', '%40', f ) # special handling due to p4 character
		f = depotMap.translate( f )
		f = f + revRange
		return f.encode( encoding )

	#
	# query lots of p4 server info
	#

	p4Start = time.time()

	p4Opened = dict ()
	print( "Fetching opened files from p4..." )
	results = p4.run_opened('-C', client[ 'Client' ], '...')
	for result in results:
		f = result[ 'depotFile' ]
		f = p4MarshalString( f )
		f = p4MakeLocalPath( f )
		f = f[ len( os.getcwd() ) + 1 :]
		p4Opened[ f.lower() ] = f

	print( " got " + str( len( p4Opened ) ) + " opened files from the server" )

	p4Files = dict ()
	p4ReadOnly = dict()
	p4Writable = dict()
	p4Increment = 100000
	p4Notify = p4Increment
	p4Count = 0
	print( "Fetching non-opened files from p4..." )

	try:
		results = p4.run_files('-e', '...#have')
	except P4.P4Exception as e:
		s = p4MarshalString( e.value )
		if "file(s) not on client" not in s:
			raise

	for result in results:
		f = result[ 'depotFile' ]
		f = p4MarshalString( f )
		f = p4MakeLocalPath( f )
		f = f[ len( os.getcwd() ) + 1 :]
		key = f.lower()
		p4Files[ key ] = f

		t = None
		if 'type' in result:
			t = result[ 'type' ]
		elif 'headType' in result:
			t = result[ 'headType' ]
		t = p4MarshalString( t )
		typeComponents = t.split('+')
		if len( typeComponents ) > 1 and 'w' in typeComponents[1]:
			p4Writable[ key ] = f
			dbg(f + " is +w")
		else:
			p4ReadOnly[ key ] = f
			dbg(f + " is +r")

		p4Count = p4Count + 1
		if options.progress and p4Count == p4Notify:
			print( str( p4Count ) + ' files so far...' )
			p4Notify = p4Notify + p4Increment

	print( " got " + str( len( p4Files ) ) + " non-opened files from the server" )

	print( "\nFetched server state in %.2fs\n" % float(time.time() - p4Start) )

	#
	# query lots of file system info
	#

	fsStart = time.time()

	fsFiles = dict()
	fsReadOnly = dict()
	fsWritable = dict()
	fsLinks = dict()
	fsLinkTargets = dict()
	fsIncrement = 100000
	fsNotify = fsIncrement
	fsCount = 0
	print( "Fetching files from fs..." )
	for root, dirs, files in os.walk( os.getcwd() ):
		for name in files:
			f = os.path.join(root, name)
			f = f[ len( os.getcwd() ) + 1 :]
			key = f.lower()
			fsFiles[ key ] = f
			result = GetFileAttributesW(f)
			if result & FILE_ATTRIBUTE_READONLY:
				fsReadOnly[ key ] = f
				dbg(f + " is RO")
			else:
				fsWritable[ key ] = f
				dbg(f + " is RW")
			fsCount = fsCount + 1
			if options.progress and fsCount == fsNotify:
				print( str( fsCount ) + ' files so far...' )
				fsNotify = fsNotify + fsIncrement
		for name in dirs:
			d = os.path.join(root, name)
			d = d[ len( os.getcwd() ) + 1 :]
			link = None
			linkTarget = None
			if os.path.islink( d ):
				link = d
				linkTarget = os.readlink( d )
				dbg( "symlink: " + link + " target: " + linkTarget )
			elif isjunction( d ):
				link = d
				linkTarget = readjunction( d )
				dbg( "junction: " + link + " target: " + linkTarget )
			if link:
				linkKey = link.lower()
				fsLinks[ linkKey ] = link
				if not os.path.isabs( linkTarget ):
					linkTarget = os.path.abspath( os.path.join( os.path.dirname( link ), linkTarget ) ) # relpath from link
				dbg( "raw link: " + link + " raw target: " + linkTarget )
				if ( linkTarget.lower().startswith( os.getcwd().lower() ) ):
					linkTarget = linkTarget[ len( os.getcwd() ) + 1 :]
					linkTargetKey = linkTarget.lower()
					fsLinkTargets[ linkTargetKey ] = linkTarget
					dbg( "sani link: " + link + " sani target: " + linkTarget )

	print( " got " + str( len( fsFiles ) ) + " files from the file system" )
	print( " got " + str( len( fsLinks ) ) + " links from the file system" )

	if len( fsLinks ):
		print( "  will skip files below " + str( len( fsLinks ) ) + " links:" )
		for k, v in fsLinks.items():
			print( "   " + k )

		if len( fsLinkTargets ):
			print( "  will preserve " + str( len( fsLinkTargets ) ) + " link targets:" )
			for k, v in fsLinkTargets.items():
				print( "   " + k )

	print( "\nFetched file system state in %.2fs\n" % float(time.time() - fsStart) )

	#
	# fill out lists of relevant data
	#

	listStart = time.time()

	missing = []
	for k, v in p4Files.items():
		if not ( k in fsFiles ):
			list.append( missing, v )

	edited = []
	for k, v in p4Files.items():
		if ( k in p4Opened ):
			list.append( edited, v )

	added = []
	for k, v in fsFiles.items():
		if not ( k in p4Files ) and ( k in p4Opened ):
			list.append( added, v )

	extra = []
	for k, v in fsFiles.items():

		if k == p4configFile:
			continue

		if not ( k in p4Files ) and not ( k in p4Opened ):
			linked = False
			for p in sorted( fsLinks.keys() ):
				if k.startswith( p ):
					linked = True
			if linked:
				continue

			list.append( extra, v )

	shouldBeWritable = []
	for k, v in fsReadOnly.items():
		if ( k in p4Writable ):
			list.append( shouldBeWritable, v )

	shouldBeReadOnly = []
	for k, v in fsWritable.items():
		if ( k in p4ReadOnly ) and not ( k in p4Opened ):
			list.append( shouldBeReadOnly, v )

	print( "Processed lists in %.2fs\n" % float(time.time() - listStart) )

	#
	# issue reports on the lists
	#

	exitCode = 0

	def safePrint( s ):
		try:
			print( s )
		except UnicodeEncodeError:
			print( s.encode(encoding=encoding, errors='replace').decode( encoding ) + ' (reencoded)' )

	if not options.quiet:
		reportStart = time.time()
		clean = True

		if len( missing ):
			clean = False
			if options.show_missing:
				exitCode = 1
				print( "\nFiles missing from your disk:" )
				for f in sorted( missing ):
					safePrint( f )
			else:
				print( "%d files missing from your disk" % len( missing ) )


		if len( edited ):
			clean = False
			if options.show_edited:
				exitCode = 1
				print( "\nFiles on your disk open for edit in a changelist:" )
				for f in sorted( edited ):
					safePrint( f )
			else:
				print( "%d files on your disk open for edit in a changelist" % len( edited ) )

		if len( added ):
			clean = False
			if options.show_added:
				exitCode = 1
				print( "\nFiles on your disk open for add in a changelist:" )
				for f in sorted( added ):
					safePrint( f )
			else:
				print( "%d files on your disk open for add in a changelist" % len( added ) )

		if len( extra ):
			clean = False
			if options.show_extra:
				exitCode = 1
				print( "\nFiles on your disk not known to the server:" )
				for f in sorted( extra ):
					safePrint( f )
			else:
				print( "%d files on your disk not known to the server" % len( extra ) )

		if len( shouldBeWritable ):
			clean = False
			if options.show_attrs:
				exitCode = 1
				print( "\nFiles on your disk that should be writable, and are read-only:" )
				for f in sorted( shouldBeWritable ):
					safePrint( f )
			else:
				print( "%d files on your disk that should be writable, and are read-only" % len( shouldBeWritable ) )

		if len( shouldBeReadOnly ):
			clean = False
			if options.show_attrs:
				exitCode = 1
				print( "\nFiles on your disk that should be read-only, but are writable:" )
				for f in sorted( shouldBeReadOnly ):
					safePrint( f )
			else:
				print( "%d files on your disk that should be read-only, but are writable" % len( shouldBeReadOnly ) )

		if clean:
			print( "\nWorking directory clean!" )
		else:
			print( "\nWorking directory dirty!" )

		print( "\nReported state in %.2fs\n" % float(time.time() - reportStart) )

	#
	# mutate workspace state
	#

	mutateStart = time.time()
	mutated = False

	if options.clean_missing and len( missing ):
		print( "\nSyncing missing files..." )
		for f in sorted( missing ):
			p4.run_sync( '-f', p4MakeDepotPath( os.path.join( os.getcwd(), f ), "#have" ) )
			safePrint( f )
			mutated = True

	if options.clean_edited and len( edited ):
		print( "\nReverting edited files..." )
		for f in sorted( edited ):
			p4.run_revert( p4MakeDepotPath( os.path.join( os.getcwd(), f ) ) )
			safePrint( f )
			mutated = True

	if options.clean_added and len( added ):
		print( "\nCleaning added files..." )
		for f in sorted( added ):
			os.chmod( f, stat.S_IWRITE )
			os.remove( f )
			p4.run_revert( p4MakeDepotPath( os.path.join( os.getcwd(), f ) ) )
			safePrint( f )
			mutated = True

	if options.clean_extra and len( extra ):
		print( "\nCleaning extra files..." )
		for f in sorted( extra ):
			os.chmod( f, stat.S_IWRITE )
			os.remove( f )
			safePrint( f )
			mutated = True

	if options.clean_attrs and len( shouldBeWritable ):
		print( "\nChanging read-only files to writable..." )
		for f in sorted( shouldBeWritable ):
			os.chmod( f, stat.S_IWRITE )
			safePrint( f )
			mutated = True

	if options.clean_attrs and len( shouldBeReadOnly ):
		print( "\nChanging writable files to read-only..." )
		for f in sorted( shouldBeReadOnly ):
			os.chmod( f, stat.S_IREAD )
			safePrint( f )
			mutated = True

	if options.clean_empty:
		print( "\nCleaning empty directories..." )
		for root, dirs, files in os.walk( os.getcwd(), topdown=False ):
			for name in dirs:
				d = os.path.join(root, name).lower()[ len( os.getcwd() ) + 1 :]
				if d in fsLinks.keys() or d in fsLinkTargets.keys():
					continue
				try:
					os.rmdir( d ) # this will fail for nonempty dirs
					safePrint( d )
					mutated = True
				except WindowsError:
					pass

	if options.verify:

		corrupted = []

		class DiffOutputHandler(P4.OutputHandler):
			def __init__(self):
				P4.OutputHandler.__init__(self)
				self.increment = 1000
				self.notify = self.increment
				self.count = 0
				self.start = time.time()

			def outputStat(self, stat):
				self.count = self.count + 1
				if options.progress and self.count == self.notify:
					velocity = float( self.count ) / float( time.time() - self.start )
					remaining = ( float( len( p4Files ) ) - float( self.count ) ) / velocity
					eta = ''
					if remaining > 3600.0:
						eta = str( int( remaining / 3600.0 ) ) + 'h'
					elif remaining > 60.0:
						eta = str( int( remaining / 60.0 ) ) + 'm'
					else:
						eta = str( int( remaining ) ) + 's' 
					print( str( self.count ) + '/' + str( len( p4Files ) ) + ' ETA: ' + eta + ' @ %.2f files/s' % ( velocity ) )
					self.notify = self.notify + self.increment

				if p4MarshalString( stat[ 'status' ] ) == 'diff':
					f = stat[ 'depotFile' ]
					f = p4MarshalString( f )
					f = p4MakeLocalPath( f )
					f = f[ len( os.getcwd() ) + 1 :]
					if not ( f in p4Opened ):
						list.append( corrupted, f )

				return P4.OutputHandler.HANDLED

		print( "\nDiffing files..." )
		p4.run_diff( '-sl', '...', handler = DiffOutputHandler() )

		if len( corrupted ):
			if options.repair:
				print( "\nRepairing corrupted files:" )
			else:
				print( "\nCorrupted files:" )
			for f in sorted( corrupted ):
				safePrint( f )
				mutated = True
				if options.repair:
					p4.run_sync( '-f', p4MakeDepotPath( os.path.join( os.getcwd(), f ), "#have" ) )
		else:
			print( "\nWorking directory verified!" )

	if mutated:
		print( "\nMutated state in %.2fs\n" % float(time.time() - mutateStart) )

	#
	# disconnect
	#

	p4.disconnect()

	if options.exit:
		exit( exitCode )

except P4.P4Exception:
	print( traceback.format_exc() )
	print( "\nP4 'info':" )
	pp.pprint( info )
	print( "\nEnvironment:" )
	pp.pprint( dict(os.environ) )
	exit( 1 )

except KeyboardInterrupt:
	exit( 1 )
