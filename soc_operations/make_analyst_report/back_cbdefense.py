# -*- coding: utf-8 -*-

import os, sys
import json, glob
from priv_module_helpers.report_helpers.mako.analyst_report.cbdefense as _writer
from monkey_tools.utils import logger_util
from monkey_tools.utils import file_util
from monkey_tools.utils import mail_util

from mako.template import Template
from mako.lookup import TemplateLookup

logger = logger_util.get_standard_logger("reportbase")
CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
OUTPUT_DIR_BASE = CURR_DIR+"/reports"

class ReportMaker(object):

	def __init__(self, customer, data, with_parse=True):
		self.customer = customer
		if with_parse:
			reportdata = self._parse_report_by_search(data)
		else:
			self.reportdata = data
		self.output_dir = "{}/{}".format(OUTPUT_DIR_BASE, self.customer)
		if not os.path.exists(self.output_dir):
			os.mkdir(self.output_dir)

		self.html_name = self.output_dir+"/analyst_report.html"

	# private

	def _make_report(self): 
		_writer.ReportMaker.write(self.reportdata, self.html_name, with_pdf=True)

def test():
	with open(CURR_DIR+"/test/stellar.json") as f:
		reportdata = json.load(f)
	rep = ReportSender("DHS3", reportdata)
	rep.operation()

def parse_search_data(data):
	pass

if __name__ == '__main__':
	test()


