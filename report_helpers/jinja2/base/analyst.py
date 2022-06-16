# -*- encoding:utf-8 -*-

import os, sys
import json, argparse, copy, base64, re
from monkey_tools.utils import template_util as j2util
from monkey_tools.utils import logger_util
from monkey_tools.utils import file_util

logger = logger_util.get_standard_logger("reportbase")

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

class AnalystReportBase(object):
	_DEFAULT_FIELD_ = "default.json"
	_CURR_DIR       = CURR_DIR
	_OUTPUT_DIR     = "../output"
	_TEMPLATE_DIR   = "../templates"
	_FIELD_DATA_DIR = "../fields"
	_FOOTER_DIR     = "../footers"
	_FOOTER_FILE    = "dhsoc.html"
	_BASE_NAME      = None
	_OUTPUT_FILE    = None
	_TEMPLATE_FILE  = None
	_FIELD_DATA     = None

	@classmethod
	def to_base64(cls, reportinfo):
		return cls.to_html(reportinfo, True)

	@classmethod
	def to_html(cls, reportinfo, to_base64=False):
		instance = cls(reportinfo)
		data = instance.render()
		if to_base64:
			return base64.b64encode(data)
		else:
			return data

	@classmethod
	def write(cls, reportinfo, file_name=None, with_pdf=False):
		instance = cls(reportinfo)
		return instance.write2file(file_name, with_pdf)

	def __init__(self, reportinfo):
		if self._FIELD_DATA is None:
			self._FIELD_DATA = self._replace_ext("json")
		if self._TEMPLATE_FILE is None:
			self._TEMPLATE_FILE = self._replace_ext("tpl.j2")

		self.template_dir = "{}/{}".format(self._CURR_DIR, self._TEMPLATE_DIR)
		self.output_dir = "{}/{}".format(self._CURR_DIR, self._OUTPUT_DIR)
		self.field_dir = "{}/{}".format(self._CURR_DIR, self._FIELD_DATA_DIR)
		self.footer_dir = "{}/{}".format(self._CURR_DIR, self._FOOTER_DIR)
		logger.debug("get field information file:{}".format(self._FIELD_DATA))
		fields = self._get_fieldinfo()
		logger.debug("make report data")
		self.reportdata = self._make_reportdata(reportinfo, fields)
	
	def write2file(self, file_name=None, with_pdf=False):
		if file_name is None:
			assert self._OUTPUT_FILE, "file name is not define yet"
			file_name = self._OUTPUT_FILE
			if not file_name.endswith(".html"):
				file_name += file_name +".html"
		j2util.write(
			self.reportdata, file_name, self._TEMPLATE_FILE, self.template_dir)
		if with_pdf:
			pdf_name = re.sub(r"\.html$", ".pdf", file_name)
			if self._FOOTER_FILE:
				footer = "{}/{}".format(self.footer_dir, self._FOOTER_FILE)
			else:
				footer = self._FOOTER_FILE
			return file_util.convert2pdf( file_name, pdf_name, footer )
		return 0

	def render(self):
		data = j2util.render(
			self.reportdata, self._TEMPLATE_FILE, self.template_dir)
		return data

	# private

	def _replace_ext(self, ext):
		assert self._BASE_NAME, "field data is not define"
		basename = os.path.basename(self._BASE_NAME)
		return re.sub(r".pyc?$", ".{}".format(ext), basename)
	
	#TODO dont merge default
	def _get_fieldinfo(self):
		def _for_this_report():
			field_file = "{}/{}".format(self.field_dir, self._FIELD_DATA)
			with open(field_file, "r") as f:
				data = json.load(f)
			return data
		logger.debug("get for this report")
		data = _for_this_report()
		logger.debug("Note:dont use default config now.")
		return data

	def _make_reportdata(self, origin, fields):
		reportdata = copy.deepcopy(fields)
		logger.debug("set generic report information")
		self._set_content(reportdata["summary"],     origin)
		self._set_content(reportdata["remediation"], origin)
		self._set_content(reportdata["date"],        origin)
		logger.debug("set table report data")
		for each in self._TABLE_FIELDS:
			self._set_content_all(reportdata[each], origin)
		return reportdata

	def _set_content_all(self, fields, reportdata):
		for each in fields:
			self._set_content(each, reportdata)

	def _set_content(self, field, reportdata, name=None):
		if name is None:
			name = field["src"]
		if name in reportdata:
			field["content"]=reportdata[name]
		else:
			field["content"]=""

