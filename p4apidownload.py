import distutils.dir_util
import ftplib
import os
import shutil
import zipfile

version_folder = 'r18.1'

# lhs is the p4 ftp url path component, rhs is the local filesystem path component (align to macros in your project system)
architectures = [ ( 'bin.ntx64', 'x64' ), ( 'bin.ntx86', 'Win32' ) ]
visual_studios = [ ( 'vs2017', 'vstudio-15.0' ) ]
runtime_libraries = [ ( 'dyn', 'md' ), ( 'dyn_vsdebug', 'mdd' ), ( 'static', 'mt' ), ( 'static_vsdebug', 'mtd' ) ]

# generate all the permutations we need
permutations = []
for a in architectures:
	for v in visual_studios:
		for r in runtime_libraries:
			permutations.append( { 'arch' : a, 'vstudio' : v, 'runtime': r } )

ftp = ftplib.FTP("ftp.perforce.com")
ftp.login()

for p in permutations:
	# download the file
	file = 'p4api_' + p['vstudio'][0] + '_' + p['runtime'][0] + '.zip'
	path = '/perforce/' + version_folder + '/' + p['arch'][0] + '/' + file
	print( 'Downloading ' + path + '...' )
	ftp.retrbinary( 'RETR ' + path, open( file, 'wb' ).write )

	# extract the archive
	print( ' Extracting ...' )
	z = zipfile.ZipFile( file, 'r' )
	version = z.infolist()[0].filename[:-1]
	z.extractall( 'download' )
	z.close()
	os.unlink( file )

	# move the lib folder to a sensible name
	libdest = 'download/' + version + '/lib/' + p['vstudio'][1] + '/' + p['arch'][1] + '/' + p['runtime'][1]
	print( ' Renaming...' )
	os.rename( 'download/' + version + '/lib', 'download/' + version + '/lib-temp' )
	os.makedirs( libdest )
	distutils.dir_util.copy_tree( 'download/' + version + '/lib-temp', libdest )
	shutil.rmtree( 'download/' + version + '/lib-temp' )

	# move all the things out of an inconvenient directory name
	print( ' Publishing...' )
	distutils.dir_util.copy_tree( 'download/' + version, 'download/p4api' )
	shutil.rmtree( 'download/' + version )

