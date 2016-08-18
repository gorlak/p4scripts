import locale
import os
import re
import stat
import subprocess
import sys
import time

import optparse
parser = optparse.OptionParser()
parser.add_option( "-c", "--clean", dest="clean", action="store_true", default=False, help="clean local workspace to match the server workspace" )
parser.add_option( "-a", "--clean_added", dest="clean_added", action="store_true", default=False, help="clean: delete and revert files that are opened for add" )
parser.add_option( "-e", "--clean_edited", dest="clean_edited", action="store_true", default=False, help="clean: revert files that are opened for edit" )
parser.add_option( "-m", "--clean_missing", dest="clean_missing", action="store_true", default=True, help="clean: restore files that are missing locally" )
parser.add_option( "-x", "--clean_extra", dest="clean_extra", action="store_true", default=True, help="clean: delete files that are unknown or deleted at #have" )
parser.add_option( "-d", "--clean_empty", dest="clean_empty", action="store_true", default=True, help="clean: delete empty directories" )
parser.add_option( "-v", "--verify", dest="verify", action="store_true", default=False, help="verify integrity of existing files")
parser.add_option( "-r", "--repair", dest="repair", action="store_true", default=False, help="repair files that fail verification")
parser.add_option( "-R", "--reset", dest="reset", action="store_true", default=False, help="completely reset everything")
( options, args ) = parser.parse_args()

if options.reset:
    options.clean = True
    options.clean_added = True
    options.clean_edited = True
    options.clean_missing = True
    options.clean_extra = True
    options.clean_empty = True
    options.verify = True
    options.repair = True

import pprint
pp = pprint.PrettyPrinter( indent=4 )

if os.name != "nt":
    print( "Not tested outside of windows\n" )
    exit( 1 )

#
# https://eklausmeier.wordpress.com/2015/10/27/working-with-windows-junctions-in-python/
#

from ctypes import *
from ctypes.wintypes import *

kernel32 = WinDLL('kernel32')
LPDWORD = POINTER(DWORD)
UCHAR = c_ubyte

GetFileAttributesW = kernel32.GetFileAttributesW
GetFileAttributesW.restype = DWORD
GetFileAttributesW.argtypes = (LPCWSTR,) #lpFileName In

INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_ATTRIBUTE_REPARSE_POINT = 0x00400

CreateFileW = kernel32.CreateFileW
CreateFileW.restype = HANDLE
CreateFileW.argtypes = (LPCWSTR, #lpFileName In
                        DWORD,   #dwDesiredAccess In
                        DWORD,   #dwShareMode In
                        LPVOID,  #lpSecurityAttributes In_opt
                        DWORD,   #dwCreationDisposition In  
                        DWORD,   #dwFlagsAndAttributes In
                        HANDLE)  #hTemplateFile In_opt

CloseHandle = kernel32.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = (HANDLE,) #hObject In

INVALID_HANDLE_VALUE = HANDLE(-1).value
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.restype = BOOL
DeviceIoControl.argtypes = (HANDLE,  #hDevice In
                            DWORD,   #dwIoControlCode In
                            LPVOID,  #lpInBuffer In_opt
                            DWORD,   #nInBufferSize In
                            LPVOID,  #lpOutBuffer Out_opt
                            DWORD,   #nOutBufferSize In
                            LPDWORD, #lpBytesReturned Out_opt
                            LPVOID)  #lpOverlapped Inout_opt

FSCTL_GET_REPARSE_POINT = 0x000900A8
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C
MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 0x4000

class GENERIC_REPARSE_BUFFER(Structure):
    _fields_ = (('DataBuffer', UCHAR * 1),)

class SYMBOLIC_LINK_REPARSE_BUFFER(Structure):
    _fields_ = (('SubstituteNameOffset', USHORT),
                ('SubstituteNameLength', USHORT),
                ('PrintNameOffset', USHORT),
                ('PrintNameLength', USHORT),
                ('Flags', ULONG),
                ('PathBuffer', WCHAR * 1))
    @property
    def PrintName(self):
        arrayt = WCHAR * (self.PrintNameLength // 2)
        offset = type(self).PathBuffer.offset + self.PrintNameOffset
        return arrayt.from_address(addressof(self) + offset).value

class MOUNT_POINT_REPARSE_BUFFER(Structure):
    _fields_ = (('SubstituteNameOffset', USHORT),
                ('SubstituteNameLength', USHORT),
                ('PrintNameOffset', USHORT),
                ('PrintNameLength', USHORT),
                ('PathBuffer', WCHAR * 1))
    @property
    def PrintName(self):
        arrayt = WCHAR * (self.PrintNameLength // 2)
        offset = type(self).PathBuffer.offset + self.PrintNameOffset
        return arrayt.from_address(addressof(self) + offset).value

class REPARSE_DATA_BUFFER(Structure):
    class REPARSE_BUFFER(Union):
        _fields_ = (('SymbolicLinkReparseBuffer', 
                        SYMBOLIC_LINK_REPARSE_BUFFER),
                    ('MountPointReparseBuffer', 
                        MOUNT_POINT_REPARSE_BUFFER),
                    ('GenericReparseBuffer', 
                        GENERIC_REPARSE_BUFFER))
    _fields_ = (('ReparseTag', ULONG),
                ('ReparseDataLength', USHORT),
                ('Reserved', USHORT),
                ('ReparseBuffer', REPARSE_BUFFER))
    _anonymous_ = ('ReparseBuffer',)

def isjunction(path):
    result = GetFileAttributesW(path)
    if result == INVALID_FILE_ATTRIBUTES:
        raise WinError()
    return bool(result & FILE_ATTRIBUTE_REPARSE_POINT)

def readjunction(path):
    reparse_point_handle = CreateFileW(path, 
                                    0,
                                    0,
                                    None,
                                    OPEN_EXISTING,
                                    FILE_FLAG_OPEN_REPARSE_POINT |
                                    FILE_FLAG_BACKUP_SEMANTICS,
                                    None)
    if reparse_point_handle == INVALID_HANDLE_VALUE:
        raise WinError()
    target_buffer = c_buffer(MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
    n_bytes_returned = DWORD()
    io_result = DeviceIoControl(reparse_point_handle, 
                                FSCTL_GET_REPARSE_POINT, 
                                None, 0,
                                target_buffer, len(target_buffer),
                                byref(n_bytes_returned),
                                None)
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

import P4
p4 = P4.P4()

try:

    #
    # connect and setup p4
    #

    p4.connect()

    # handle non-unicode servers by marshalling raw bytes to local encoding
    if not p4.server_unicode:
        p4.encoding = 'raw'

    def p4MarshalString( data ):
        if isinstance( data, str ):
            return data
        else:
            return data.decode( locale.getpreferredencoding() )

    # handle the p4config file special as its always hanging out, if it exists
    p4configFile = p4.p4config_file
    if p4configFile != None:
        p4configFile = p4configFile.lower()[ len( os.getcwd() ) + 1 :]

    # setup client
    client = p4.fetch_client()
    clientMap = P4.Map( client[ 'View' ] )
    clientRoot = client[ 'Root' ]

    if ( clientRoot[-1] != '\\' ) and ( clientRoot[-1] != '/' ):
        clientRoot += '/'

    clientSlashesFixed = re.sub( r'\\', r'\\\\', clientRoot )

    def p4MakeLocalPath( f ):
        f = clientMap.translate( f )
        f = re.sub( '//' + re.escape( client[ 'Client' ] ) + '/(.*)', clientSlashesFixed + '\\1', f, 0, re.IGNORECASE )
        f = re.sub( r'/', r'\\', f )
        f = re.sub( r'%40', '@', f ) # special handling due to p4 character
        f = re.sub( r'%23', '#', f ) # special handling due to p4 character
        f = re.sub( r'%2A', '*', f ) # special handling due to p4 character
        f = re.sub( r'%25', '%', f ) # special handling due to p4 character
        return f

    #
    # query lots of info
    #

    p4Opened = dict ()
    try:
        print( "Fetching opened files from p4..." )
        results = p4.run_opened('-C', client[ 'Client' ], '...')
        for result in results:
            f = result[ 'depotFile' ]
            f = p4MarshalString( f )
            f = p4MakeLocalPath( f )
            f = f[ len( os.getcwd() ) + 1 :]
            p4Opened[ f.lower() ] = f
    except KeyboardInterrupt:
        exit(1) 

    print( " got " + str( len( p4Opened ) ) + " files from the server" )

    p4Files = dict ()
    try:
        print( "Fetching depot files from p4..." )
        results = p4.run_files('...#have')
        for result in results:
            if p4MarshalString( result[ 'action' ] ).find( "delete" ) >= 0:
                continue
            f = result[ 'depotFile' ]
            f = p4MarshalString( f )
            f = p4MakeLocalPath( f )
            p4Files[ f.lower()[ len( os.getcwd() ) + 1 :] ] = f
    except KeyboardInterrupt:
        exit(1)

    print( " got " + str( len( p4Files ) ) + " files from the server" )

    fsFiles = dict()
    fsLinks = dict()
    fsLinkTargets = dict()
    try:
        print( "Fetching files from fs..." )
        for root, dirs, files in os.walk( os.getcwd() ):
            for name in files:
                f = os.path.join(root, name)
                fsFiles[ f.lower()[ len( os.getcwd() ) + 1 :] ] = f
            for name in dirs:
                d = os.path.join(root, name)
                link = None
                linkTarget = None
                if os.path.islink( d ):
                    link = d
                    linkTarget = os.readlink( d )
                elif isjunction( d ):
                    link = d
                    linkTarget = readjunction( d )
                if link:
                    fsLinks[ link.lower()[ len( os.getcwd() ) + 1 :] ] = link
                    if not os.path.isabs( linkTarget ):
                        linkTarget = os.path.abspath( os.path.join( os.path.dirname( linkTarget ), linkTarget ) )
                    if ( linkTarget.lower().startswith( os.getcwd().lower() ) ):
                        fsLinkTargets[ linkTarget.lower()[ len( os.getcwd() ) + 1 :] ] = linkTarget
    except KeyboardInterrupt:
        exit( 1 )

    print( " got " + str( len( fsFiles ) ) + " files from the file system" )

    if len( fsLinks ):
        print( "  will skip files below " + str( len( fsLinks ) ) + " links:" )
        for k, v in fsLinks.items():
            print( "   " + k )

        if len( fsLinkTargets ):
            print( "  will preserve " + str( len( fsLinkTargets ) ) + " link targets:" )
            for k, v in fsLinkTargets.items():
                print( "   " + k )

    #
    # fill out lists of relevant data
    #

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
                continue;

            list.append( extra, v )

    #
    # do what we came here to do
    #

    report = (not options.clean)
    if report:
        clean = True

        if len( missing ):
            clean = False
            print( "\nFiles missing from your disk:" )
            for f in sorted( missing ):
                print( f )

        if len( edited ):
            clean = False
            print( "\nFiles on your disk open for edit in a changelist:" )
            for f in sorted( edited ):
                print( f )

        if len( added ):
            clean = False
            print( "\nFiles on your disk open for add in a changelist:" )
            for f in sorted( added ):
                print( f )

        if len( extra ):
            clean = False
            print( "\nFiles on your disk not known to the server:" )
            for f in sorted( extra ):
                print( f )

        if clean:
            print( "\nWorking directory clean!" )

    elif options.clean:

        if options.clean_missing:
            print( "\nSyncing missing files..." )
            for f in sorted( missing ):
                p4.run_sync( '-f', f )
                print( f );

        if options.clean_edited:
            print( "\nReverting edited files..." )
            for f in sorted( edited ):
                p4.run_revert( f )
                print( f );

        if options.clean_added:
            print( "\nCleaning added files..." )
            for f in sorted( added ):
                os.chmod( f, stat.S_IWRITE )
                os.remove( os.path.join( os.getcwd(), f ) )
                p4.run_revert( f )
                print( f );

        if options.clean_extra:
            print( "\nCleaning extra files..." )
            for f in sorted( extra ):
                os.chmod( f, stat.S_IWRITE )
                os.remove( os.path.join( os.getcwd(), f ) )
                print( f );

        if options.clean_empty:
            print( "\nCleaning empty directories..." )
            for root, dirs, files in os.walk( os.getcwd(), topdown=False ):
                for name in dirs:
                    d = os.path.join(root, name).lower()[ len( os.getcwd() ) + 1 :] 
                    if d in fsLinks.keys() or d in fsLinkTargets.keys():
                        continue
                    try:
                        os.rmdir( d ) # this will fail for nonempty dirs
                        d = d[ len( os.getcwd() ) + 1 :]
                        print( d )
                    except WindowsError:
                        pass

    if options.verify:

        try:
            print( "\nDiffing files..." )
            results = p4.run_diff( '-se', '...' )
        except KeyboardInterrupt:
            exit( 1 )

        corrupted = []
        for result in results:
            f = result[ 'depotFile' ]
            f = p4MarshalString( f )
            f = p4MakeLocalPath( f )
            f = f[ len( os.getcwd() ) + 1 :]
            list.append( corrupted, f )

        if len( corrupted ):
            if options.repair:
                print( "\nRepairing corrupted files:" )
            else:
                print( "\nCorrupted files:" )
            for f in sorted( corrupted ):
                print( f );
            if options.repair:
                p4.run_sync( '-f', f + "#have" )
        else:
            print( "\nWorking directory verified!" )

except P4.P4Exception:
    for e in p4.errors:
        print( e )

#
# shutdown
#

p4.disconnect()
