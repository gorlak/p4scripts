import os
import sys
import time

import optparse
parser = optparse.OptionParser()
parser.add_option("-s", "--server", dest="server", default=False, help="display server info")
parser.add_option("-c", "--counters", dest="counters", default=False, help="display counters")
parser.add_option("-i", "--interval", dest="interval", default=1.0, help="time interval in seconds")
(options, args) = parser.parse_args()

import pprint
pp = pprint.PrettyPrinter(indent=4)

import P4
p4 = P4.P4()

try:
	p4.connect()
  
	while( 1 ):

		os.system('cls')

		if options.server:
			result = p4.run('info')
			for key in result[0]:
				print(key, '=', result[0][key])
			print("") #newline

		if options.counters:
			results = p4.run('counters')
			for result in results:
				print( 'Counter \'{}\': {}'.format( result['counter'], result['value'] ) )
			print("") #newline

		results = p4.run('monitor', 'show')
		#pp.pprint(results)

		results = sorted(results, key=lambda result: result['time'], reverse=True)
		#pp.pprint(results)

		for result in results:
			print( '{}/{:5}: {} - {:20} - {}'.format( result['status'], result['id'], result['time'], result['user'], result['command'] ) )

		try:
			time.sleep( float( options.interval ) )
		except KeyboardInterrupt:
			exit(0)

	p4.disconnect()

except P4.P4Exception:
	for e in p4.errors:
		print(e)