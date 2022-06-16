# -*- coding: utf-8 -*-

import os, sys
import json, glob
from priv_module_helpers.report_helpers.mako.analyst_report.stellar import ReportMaker as _writer
from monkey_tools.product.stellar import convert2reportdata as _convert
from monkey_tools.utils import logger_util
from monkey_tools.utils import file_util
from monkey_tools.utils import mail_util
from monkey_tools.utils import time_util as _tu

from mako.template import Template
from mako.lookup import TemplateLookup

logger = logger_util.get_standard_logger("reportbase")
CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
OUTPUT_DIR_BASE = CURR_DIR+"/reports"
_DEFAULT_TEMP_DIR = CURR_DIR+"/templates"

def get_template(_file, _dirs=None):
	if _dirs is None:
		_dirs = [_DEFAULT_TEMP_DIR]
	elif not _DEFAULT_TEMP_DIR in _dirs:
		_dirs.append(_DEFAULT_TEMP_DIR)
	myLookup = TemplateLookup( directories=_dirs,
				input_encoding="utf-8",
				output_encoding="utf-8")
	return myLookup.get_template(_file)

class ReportSender(object):
	WITH_PASSOWRD = True

	def __init__(self, customer, reportdata):
		self.customer = customer
		self.reportdata = reportdata
		with open(CONF_DIR+"/config.json") as f:
			self.config = json.load(f)
		customer_cfg = self._get_customer_conf()
		customer_fname = customer_cfg["formal_name"]
		today = _tu.get_date(_tu.UNIX)
		fname_tail = today.replace("-","")
		self.output_dir = "{}/{}".format(OUTPUT_DIR_BASE, self.customer)
		if not os.path.exists(self.output_dir):
			os.mkdir(self.output_dir)

		self.html_name = self.output_dir+"/analyst_report.html"
		self.simple_zip_name = "{}様_Alert解析報告書_{}.zip".format(
				customer_fname, fname_tail)
		self.zip_name = u"{}/{}".format(self.output_dir, self.simple_zip_name)
	
	def operation(self):
		self._make_report()
		self._make_zip_file()
		self._send_mail()
		self._clean_files()

	# private

	def _make_zip_file(self):
		pdf_file = self.html_name.replace(".html", ".pdf")
		res = file_util.file_to_zip(pdf_file, self.zip_name, random=True)
		self.password = res[1]

	def _get_customer_conf(self):
		return self.config["customers"][self.customer]

	def _clean_files(self):
		file_name = self.html_name
		if os.path.exists(file_name):
			os.remove(file_name)
		file_name = self.html_name.replace(".html", ".pdf")
		if os.path.exists(file_name):
			os.remove(file_name)
		file_name = self.zip_name
		if os.path.exists(file_name):
			os.remove(file_name)

	def _make_report(self): 
		if "_raw" in self.reportdata:
			rawdata = self.reportdata["_raw"]
		elif "rawdata" in self.reportdata:
			rawdata = self.reportdata["rawdata"]
		else:
			rawdata = None
		if rawdata:
			try:
				rawdata = json.loads(rawdata)
			except Exception as e:
				rawdata = None
		reportdata = _convert.convert2reportdata(self.reportdata, rawdata=rawdata)
		_writer.write(reportdata, self.html_name, with_pdf=True)

	def _send_mail(self):
		def send_each_mail(taddr, subject, body, attach_file=None, attach_name=None):
			faddr  = sender_info["from"]
			server = mail_cfg["server"]
			port   = mail_cfg["port"]
			is_ssl = mail_cfg["ssl"]
			if is_ssl:
				account = sender_info["account"]["user"]
				password = sender_info["account"]["password"]
			msg = mail_util.set_msg(
					faddr, taddr, subject, body, attach_file, attach_name)
			if is_ssl:
				mail_util.ssend( server, faddr, taddr, msg, account, password, port )
			else:
				mail_util.send( server, faddr, taddr, msg )
		customer_info = self._get_customer_conf()
		mail_cfg = self.config["mail"]
		customer_fname = customer_info["formal_name"]
		mail_addr      = customer_info["to"].split(",")
		sender_name    = customer_info["from"]
		sender_info    = mail_cfg[sender_name]
		body_data = { "customer_name" : customer_fname,
						"product" : "Stellarcyber Starlight",
						"password" : self.password }
		subject = mail_cfg["subject"].replace(
				'{severity}', self.reportdata["risklevel_jpn"])
		template = get_template(self.config["mail"]["templates"]["send_report"])
		body = template.render(**body_data)
		send_each_mail(mail_addr, subject, body, self.zip_name, self.simple_zip_name)
		subject = u"[パスワードのご連絡] "+subject
		template = get_template(self.config["mail"]["templates"]["send_password"])
		body = template.render(**body_data)
		send_each_mail(mail_addr, subject, body)

def test():
	with open(CURR_DIR+"/test/stellar.json") as f:
		reportdata = json.load(f)
	rep = ReportSender("DHS3", reportdata)
	rep.operation()

if __name__ == '__main__':
	test()


