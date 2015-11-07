import os
import re
import subprocess
import sys
import time

import optparse
parser = optparse.OptionParser()
parser.add_option( "-r", "--repair", dest="repair", action="store_true", default=False, help="repair corrupt files" )
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

  try:
    print( "Diffing files..." )
    results = p4.run_diff( '-se', '...' )
  except KeyboardInterrupt:
    exit( 1 )

  corrupted = []
  for result in results:
    f = result[ 'depotFile' ]
    f = MakeLocalPath( f )
    f = f.replace( os.getcwd() + '\\', '' )
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

  p4.disconnect()

except P4.P4Exception:
  for e in p4.errors:
    print( e )
