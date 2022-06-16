# -*- encoding:utf-8 -*-

import os, sys, codecs
import argparse, base64, json

reload(sys)
sys.setdefaultencoding('utf-8')
sys.stdout = codecs.lookup('utf-8')[-1](sys.stdout)

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

from analyst_report import helix_squid

TOP_HELP ='''
make reprot data for DHSOC MSS/MDR.
ex1)
	python commands.py -t analyst --subtype helix:squid -d $(cat sample.json | base64) -b
ex2)
	python commands.py -t analyst --subtype helix:squid -d $(cat sample.json | base64) -b -o '/tmp/report.html'
'''

parser = argparse.ArgumentParser(description=TOP_HELP)

def _set_argement():
	parser.add_argument('-t', '--type',
		choices=['monthly', 'analyst'],
		help='select report type. monthly or analyst report.') 
	parser.add_argument('-s', '--subtype',
		choices=['helix:squid', 'helix:paloalto', 'cbdefense'],
		help='select report based product etc.') 
	parser.add_argument('-d', '--data',
		help='set report data by json or base64. if you use base64, need to set base64 flag.')
	parser.add_argument('-b', '--base64', action="store_true")
	parser.add_argument('-if', '--input_file', action="store_true")
	parser.add_argument('-p', '--pdf',    action="store_true")
	parser.add_argument('-o', '--output',
		default=None,
		help='write output to specified file. this is need to set with -w.')
	parser.add_argument('-l', '--log', action="store_true",
			help="logging if set this.")

def _make_monthly(args):
	print report_type

def _make_analyst(args):
	def get_reportdata(is_b64, is_file, data):
		if is_file:
			file_name = data
			with open(file_name, "r") as f:
				data = f.read()
		if is_b64:
			jsondata = base64.b64decode(data)
		else:
			jsondata = data
		return json.loads(jsondata)

	def make_report(cls, data, args):
		if args.output:
			output_file = args.output
			if args.pdf:
				code = cls.write(data, output_file, with_pdf=True)
			else:
				code = cls.write(data, output_file)
			return code
		else:
			return cls.to_base64(data)

	if args.subtype == 'helix:squid':
		cls = helix_squid.ReportMaker
	else:
		assert False, "unknown report type"

	data = get_reportdata(args.base64, args.input_file, args.data)
	return make_report(cls, data, args)

def main():
	_set_argement()
	args = parser.parse_args()
	if args.type == 'monthly':
		print _make_monthly(args)
	else:
		print _make_analyst(args)

if __name__ == '__main__':
	import logging
	logging.basicConfig(level=logging.DEBUG)
	logger = logging.getLogger("command")
	main()

