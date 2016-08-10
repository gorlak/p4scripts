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
( options, args ) = parser.parse_args()

import pprint
pp = pprint.PrettyPrinter( indent=4 )

import P4
p4 = P4.P4()

try:

  if os.name != "nt":
    print( "Not tested outside of windows\n" )
    exit( 1 )

  p4.connect()

  client = p4.fetch_client()
  clientMap = P4.Map( client[ 'View' ] )
  clientRoot = client[ 'Root' ]

  # handle the p4config file special as its always hanging out, if it exists
  p4configFile = p4.p4config_file
  if p4configFile != None:
    p4configFile = p4configFile.lower().replace( os.getcwd().lower() + '\\', '' )

  if ( clientRoot[-1] != '\\' ) and ( clientRoot[-1] != '/' ):
    clientRoot += '/'

  clientSlashesFixed = re.sub( r'\\', r'\\\\', clientRoot )

  def MakeLocalPath( f ):
    f = clientMap.translate( f )
    f = re.sub( '//' + re.escape( client[ 'Client' ] ) + '/(.*)', clientSlashesFixed + '\\1', f, 0, re.IGNORECASE )
    f = re.sub( r'/', r'\\', f )
    f = re.sub( r'%40', '@', f ) # special handling due to p4 character
    f = re.sub( r'%23', '#', f ) # special handling due to p4 character
    f = re.sub( r'%2A', '*', f ) # special handling due to p4 character
    f = re.sub( r'%25', '%', f ) # special handling due to p4 character
    return f

  p4Opened = dict ()
  try:
    print( "Fetching opened files from p4..." )
    results = p4.run_opened('-C', client[ 'Client' ], '...')
    for result in results:
      f = result[ 'depotFile' ]
      f = MakeLocalPath( f )
      f = f.replace( os.getcwd() + '\\', '' )
      p4Opened[ f.lower() ] = f
  except KeyboardInterrupt:
    exit(1) 

  print( " got " + str( len( p4Opened ) ) + " files from the server")

  p4Files = dict ()
  try:
    print( "Fetching depot files from p4..." )
    results = p4.run_files('...#have')
    for result in results:
      if result[ 'action' ].find( "delete" ) >= 0:
        continue
      f = result[ 'depotFile' ]
      f = MakeLocalPath( f )
      p4Files[ f.lower().replace( os.getcwd().lower() + '\\', '' ) ] = f
  except KeyboardInterrupt:
    exit(1)

  print( " got " + str( len( p4Files ) ) + " files from the server")

  fsFiles = dict()
  try:
    print( "Fetching files from fs..." )
    for root, dirs, files in os.walk( os.getcwd() ):
      for name in files:
        f = os.path.join(root, name)
        fsFiles[ f.lower().replace( os.getcwd().lower() + '\\', '' ) ] = f
  except KeyboardInterrupt:
    exit( 1 )

  print( " got " + str( len( fsFiles ) ) + " files from the file system")

  report = (not options.clean)

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
      list.append( extra, v )

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

    print( "\nCleaning empty directories..." )
    for root, dirs, files in os.walk( os.getcwd(), topdown=False ):
      for name in dirs:
        try:
          d = os.path.join(root, name)
          os.rmdir( d )
          d = d.replace( os.getcwd() + '\\', '' )
          print( d )
        except WindowsError:
          pass

  else:
    print( "Unknown operation!" )

  p4.disconnect()

except P4.P4Exception:
  for e in p4.errors:
    print( e )
