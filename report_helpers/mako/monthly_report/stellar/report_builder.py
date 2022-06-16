# -*- encoding:utf-8 -*-

import os, sys
from logging import getLogger
import xml.etree.ElementTree as ET

import json, argparse, copy, base64, re, copy, yaml, glob
import unicodedata

from mako.template import Template
from mako.lookup import TemplateLookup

from monkey_tools.utils import file_util
from monkey_tools.utils import time_util as _tu

logger = getLogger()
CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_DEFAULT_TEMP_DIR = CURR_DIR+"/templates"
_TEMP_FILE = "report.mk.tmpl"
_GENERAL_REPORT_INFO = "reportinfo.yaml"

_KILLCHAIN_DESC_TABLE  = "alert_killchain_desc.json"
_ALERT_TYPE_DESC_TABLE = "alert_type_desc.json"

def get_template(_file, _dirs=None, language="japanese"):
	if _dirs is None:
		if language == "japanese":
			_dirs = [_DEFAULT_TEMP_DIR]
		else:
			_dirs = [_DEFAULT_TEMP_DIR+"/en"]
	elif not _DEFAULT_TEMP_DIR in _dirs:
		_dirs.append(_DEFAULT_TEMP_DIR)
	myLookup = TemplateLookup( directories=_dirs,
				input_encoding="utf-8",
				output_encoding="utf-8")
	return myLookup.get_template(_file)


class ReportBuilder(object):
	REPORT_DIR = None
	DATA_DIR = None
	_MONTH_DIFF = -1
	_EXCLUDE_DATE = []

	@classmethod
	def set_dir(cls, report_dir, data_dir):
		cls.REPORT_DIR = report_dir
		cls.DATA_DIR = data_dir

	@classmethod
	def set_month(cls, month_diff):
		cls._MONTH_DIFF = month_diff

	@classmethod
	def set_excludes(cls, excludes):
		cls._EXCLUDE_DATE = excludes

	@classmethod
	def make_report(cls, customer_name, tableinfo, alertinfo, geninfo,
			to_pdf=False, make_html=True):
		logger.debug("make report for {}.".format(customer_name))
		alerts = alertinfo["alerts"]
		sender_name = alertinfo["sender_name"]
		language = alertinfo["language"]
		formal_name = alertinfo["formal_name"]
		obj = cls(customer_name, formal_name, sender_name, tableinfo, alerts, geninfo, language, alertinfo["user_config"])
		if make_html:
			obj.make_html()
		obj.make_pdf()

	@classmethod
	def make_pdf_only(cls, customer_name, alertinfo, geninfo):
		logger.debug("make pdf only for {}.".format(customer_name))
		alerts = alertinfo["alerts"]
		sender_name = alertinfo["sender_name"]
		language = alertinfo["language"]
		formal_name = alertinfo["formal_name"]
		obj = cls(customer_name, formal_name, sender_name, None, alerts, geninfo, language, alertinfo["user_config"], make_html=False)
		obj.make_pdf()

	
	def __init__(self, customer_name, formal_name, sender_name, tableinfo, alerts, geninfo, language, user_config, make_html=True):
		self.customer_name = customer_name
		self.customer_dir = self.REPORT_DIR+"/{}".format(customer_name)
		self.formal_name = formal_name
		self.sender_name = sender_name
		self.language = language
		self.config = user_config
		if self.language == "english":
			self.file_name = "report_en"
		else:
			self.file_name = "report"
		self.month_diff = self._MONTH_DIFF
		#geninfo = self.DATA_DIR+"/general/"+_GENERAL_REPORT_INFO
		#with open(geninfo) as f:
		#	reportdata=yaml.safe_load(f)
		reportdata=geninfo
		info = self._make_reportinfo(alerts)
		if make_html:
			self._set_reportinfo(info, reportdata, tableinfo)
		self.reportdata = reportdata
		footer = self.reportdata["format"]["footer"][self.sender_name]
		self.footer_file = "{}/footer/{}".format(self.customer_dir, footer)
	
	def make_html(self):
		_template = get_template(_TEMP_FILE, language=self.language)
		self.reportdata["alertdata"]["alert_detail_table"] = { "fields":[] }
		with open("./tmp/data.json", "w") as wf: #TODO
			json.dump(self.reportdata, wf, indent=4) #TODO
		self.html = _template.render(**self.reportdata)
		self.html = unicodedata.normalize("NFC", self.html.decode()).encode()
		with open("{}/{}.html".format(
			self.customer_dir, self.file_name), "wf") as wf:
			wf.write(self.html)
	
	def make_pdf(self):
		file_util.convert2pdf(
				self.customer_dir+"/{}.html".format(self.file_name),
				self.customer_dir+"/{}.pdf".format(self.file_name),
				self.footer_file)

	# private

	def _make_reportinfo(self, alerts):
		result = {"product" : "Stellar Cyber社製 Starlight"}
		if self.language == "japanese":
			month = _tu.get_month(self.month_diff)
			lastday = _tu.get_last_day(month)
			result["report_period"] = "{}〜{}".format(month+"1日", lastday)
			result["report_month"] = month
		else:
			month = _tu.get_month(self.month_diff, date_type=_tu.ENG)
			lastday = _tu.get_last_day(month, date_type=_tu.ENG)
			firstday = "{0} 01 {1}".format(*(month.split(" ")))
			result["report_period"] = "{} to {}".format(firstday, lastday)
			result["report_month"] = month
		return result

	def _set_reportinfo(self, info, _data, tableinfo):
		def _set_target(info, _data):
			tgt = _data["report_target"]
			tgt["customer_name"] = self.formal_name
			tgt["report_month"] = info["report_month"]
			for each in tgt["table"]["contents"]:
				each["content"] = info[each["src"]]

		def _set_headers(info, _data):
			hdr = _data["headers"]
			hdr["company"] = hdr["sender"][self.sender_name]
			if self.language == "japanese":
				_date=_tu.get_date()
			else:
				_date=_tu.get_date(_tu.ENG)
			hdr["date"] = _date

		def _set_format(info, _data):
			logo = _data["format"]["logo"]
			logo["use"] = logo[self.sender_name]
			title = _data["headers"]["title"]
			title["use"] = title[self.sender_name]

		def _set_security_news(_data):
			def _parse_each_xml(each):
				title = each.find("title").text
				content = each.find("content").text
				return { "title" : title, "content" : content }

			section = {"news" : [] }
			data_dir = self.DATA_DIR+"/news/"
			if self.language == "english":
				data_dir += "en/"
			newsfiles = glob.glob(data_dir+"*.xml")

			newsfiles.sort()
			for each in newsfiles:
				try:
					root = ET.parse(each)
					newslist = root.findall("each")
					if newslist:
						for eachnews in root.findall("each"):
							value = _parse_each_xml(eachnews)
							section["news"].append( value )
					else:
						value = _parse_each_xml(root)
						section["news"].append( value )
				except Exception as e:
					logger.warning("xml parse error {}".format(each))
					logger.exception(e)
			_data["security_news"] = section

		def _set_other_comment(_data):
			def _parse_each_xml(each):
				root = ET.parse(each)
				title = root.find("title").text
				content = root.find("content").text
				return { "title" : title, "content" : content }

			section = _data["userdata"]["comments"]
			_dir = "/{}/userdata/{}/comments".format(
				self.DATA_DIR, self.customer_name)
			if self.language == "english":
				_dir += "/en"
			_dir += "/*.xml"
			commentsfiles = glob.glob(_dir)
			commentsfiles.sort()
			for each in commentsfiles:
				try:
					value = _parse_each_xml(each)
					section.append( value )
				except Exception as e:
					logger.warning("xml parse error {}".format(each))
					logger.exception(e)

		def _set_table(data, index4descs=None):
			def make_each(field, indexes, hclass):
				result = []
				for i in range(0, len(field)):
					each = { "content" : str(field[i]) }
					if i in indexes:
						if hclass == "content":
							each["class"] = "desc_"+hclass
						else:
							each["class"] = hclass
					else:
						each["class"] = "min_"+hclass
					result.append(each)
				return result

			if isinstance(index4descs, int):
				index4descs = [index4descs]
			elif isinstance(index4descs, basestring):
				index4descs = [int(index4descs)]
			elif index4descs is None:
				index4descs = []

			data["header"] = make_each(data["header"], index4descs, "item")
			data["fields"] = [ make_each(each, index4descs, "content")
						for each in data["fields"] ] 

		def correction_chapter(num, _sec): 
			for each in _sec.values():
				if each["number"] >= num:
					each["number"] -= 1

		_set_target(info, _data)
		_set_headers(info, _data)
		_set_format(info, _data)
		_set_security_news(_data)
		_data["appendix"] = {}

		_sec = _data["headers"]["sections"]

		_otherconf = self.config.get("other")

		_data["alertdata"] = {}
		alertnum = 0
		alertnum_6month = 0
		for each in tableinfo["severity_table"]["fields"]:
			alertnum += each[1]
		if tableinfo["monthlychart_table"]:
			for each in tableinfo["monthlychart_table"]["fields"]:
				alertnum_6month += each[1]
			_set_table( tableinfo["monthlychart_table"],    [0]  )
		_set_table( tableinfo["severity_table"],            [2]  )
		_set_table( tableinfo["topnum_by_app_table"],       []   )
		_set_table( tableinfo["topnum_by_srcip_table"],     []   )
		_set_table( tableinfo["topnum_by_dstip_table"],     []   )
		_set_table( tableinfo["topnum_by_dstip_geo_table"], []   )
		_set_table( tableinfo["killchain_table"],           []   )
		_set_table( tableinfo["killchain_desc_table"],      [2]  )
		_set_table( tableinfo["alert_type_table"],          []   )
		_set_table( tableinfo["alert_type_desc_table"],     [1]  )
		_data["alertdata"]["alert_num"] = alertnum
		_data["alertdata"]["alert_num_6month"] = alertnum_6month
		_data["alertdata"].update(tableinfo)
		_data["userdata"] = { "comments" : [], "conclusion" : None }
		_set_other_comment(_data)

