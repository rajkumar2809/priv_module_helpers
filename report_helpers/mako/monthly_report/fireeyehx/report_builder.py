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
		result = {"product" : "FireEye HX"}
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

		def _set_agent_release(_data):
			section = _data["software_release"]
			hdrs = [ each["name"] for each in _data["tableformat"]["server_release"]["column"] ]
			_server = section["server_release"]
			values = []
			for each in _server["supported"]:
				values.append( [each["version"], each["release_date"],
								each["end_of_release_test"] ] )
			_server["table"] = {"header" : hdrs, "fields" : values}
			_agent = section["agent_release"]
			if self.language == "japanese":
				fname = "{}/agents/versions.csv".format(self.DATA_DIR)
			else:
				fname = "{}/agents/en/versions.csv".format(self.DATA_DIR)
			if self.language == "japanese":
				hdrs = ["Agent",      "インストール可能機器",
						"リリース日", "検証状況（検証完了日）※" ]
			else:
				hdrs = ["Agent",      "Support OS",
						"release date", "Status of the verification (Completion date)" ]
			rawdata = file_util.parse_csv(fname)
			values = []
			for each in rawdata:
				values.append( [ each[k] for k in hdrs ] )
			_agent["table"] = {"header" : hdrs, "fields" : values}
		
		def _set_config_history_result(_data):
			def _parse_each_xml(each):
				root = ET.parse(each)
				title = root.find("title").text.strip()
				date = root.find("date").text.strip()
				desc = root.find("description").text.strip()
				return [ title, date, desc ]

			values = []
			_dir = "{}/userdata/{}/config_history".format(
				self.DATA_DIR, self.customer_name)
			if self.language == "english":
				_dir += "/en"
			_dir += "/*.xml"
			resultsfile = glob.glob(_dir)
			resultsfile.sort()
			for each in resultsfile:
				try:
					value = _parse_each_xml(each)
					values.append( value )
				except Exception as e:
					logger.warning("xml parse error {}".format(each))
					logger.exception(e)
			hdrs = [ each["name"] for each in _data["tableformat"]["config_history"]["column"] ]
			_data["config_history"]["results"] = {
					"header" : hdrs, "fields" :values }

		def _set_digitalrisk_vuln_ipaddr_result(_data):
			fname = "{}/userdata/{}/digitalrisk/vuln_ipaddr.csv".format(
				self.DATA_DIR, self.customer_name)
			if os.path.exists(fname):
				data = file_util.parse_csv(fname)
				headers = [ "オープンポート",
							"ドメイン",
							"CVE" ]
				tmp = {}
				for each in data:
					ipaddr = each.pop("IPアドレス")
					if not ipaddr in tmp:
						tmp[ipaddr] = {}
					if each["CVE"] and len(each["CVE"])>0:
						is_vuln = True
					else:
						is_vuln = False
					if not is_vuln in tmp[ipaddr]:
						tmp[ipaddr][is_vuln] = []
					values = [ each[k] for k in headers ]
					tmp[ipaddr][is_vuln].append( values )
				results = []
				for ipaddr, rawdata in tmp.items():
					values = []
					for is_vuln in (True, False):
						if is_vuln in rawdata:
							values.extend(rawdata[is_vuln])
					results.append({"ipaddr" : "IPアドレス:{}".format(ipaddr),
									"header" : headers,
									"fields" : values })
				_data["digitalrisk"]["vuln_ipaddr"]["results"] = results
			else:
				_data["digitalrisk"]["vuln_ipaddr"]["results"] = None

		def _set_digitalrisk_dataleak_result(_data):
			fname = "{}/userdata/{}/digitalrisk/dataleak.csv".format(
				self.DATA_DIR, self.customer_name)
			if os.path.exists(fname):
				data = file_util.parse_csv(fname)
				tmp = {}
				headers = [ "登録キーワード",
							"データソース" ]
				for each in data:
					keyword = each["キーワード"]
					if not keyword in tmp:
						tmp[keyword] = []
					tmp[keyword].append(
						[ each["キーワード"], each["データソース"] ])
				values = []
				for keyword, rawdata in tmp.items():
					values.extend(rawdata)
				results = [{"header" : headers,
							"fields" : values } ]
				_data["digitalrisk"]["dataleak"]["results"] = results
			else:
				_data["digitalrisk"]["dataleak"]["results"] = None

		def _set_digitalrisk_impersonate_domain_result(_data):
			fname = "{}/userdata/{}/digitalrisk/impersonate_domain.csv".format(
				self.DATA_DIR, self.customer_name)
			if os.path.exists(fname):
				data = file_util.parse_csv(fname)
				tmp = {}
				headers = [ "なりすましドメイン",
							"なりすましドメインのIPアドレス",
							"関連する脅威アクター",
							"ホストIPアドレスへの通信" ]
				for each in data:
					top_domain = each.pop("登録ドメイン")
					if not top_domain in tmp:
						tmp[top_domain] = {}
					severity = each["ホストIPアドレスへの通信"]
					if not severity in tmp[top_domain]:
						tmp[top_domain][severity] = []
					values = [ each[k] for k in headers ]
					tmp[top_domain][severity].append( values )
				results = []
				headers[2] = headers[2] + "※1"
				headers[3] = headers[3] + "※2"
				for top_domain, rawdata in tmp.items():
					values = []
					for sev in ("有", "無"):
						if sev in rawdata:
							values.extend(rawdata[sev])
					results.append({"top_domain" : "登録ドメイン:{}".format(
													top_domain),
									"header"     : headers,
									"fields"     : values } )
				_data["digitalrisk"]["impersonate_domain"]["results"] = results

			else:
				_data["digitalrisk"]["impersonate_domain"]["results"] = None

		def _set_digitalrisk_monitor_target_result(_data):
			fname = "{}/userdata/{}/digitalrisk/monitor_targets.csv".format(
				self.DATA_DIR, self.customer_name)
			data = file_util.parse_csv(fname)
			headers = [ "区分",
						"登録内容" ]
			values = [ [ each[k] for k in headers ] for each in data ]
			results ={  "header" : headers,
						"fields" : values }
			_data["digitalrisk"]["monitor_target"]["results"] = results

		def _set_digitalrisk_vuln_domain_result(_data):
			fname = "{}/userdata/{}/digitalrisk/vuln_domain.csv".format(
				self.DATA_DIR, self.customer_name)
			if os.path.exists(fname):
				data = file_util.parse_csv(fname)
				tmp = {}
				headers = [ "サブドメイン",
							"IPアドレス",
							"CVE",
							"オープンポート",
							"危険度" ]
				for each in data:
					top_domain = each.pop("トップドメイン")
					if not top_domain in tmp:
						tmp[top_domain] = {}
					severity = each["危険度"]
					if not severity in tmp[top_domain]:
						tmp[top_domain][severity] = []
					values = [ each[k] for k in headers ]
					tmp[top_domain][severity].append( values )
				results = []
				for top_domain, rawdata in tmp.items():
					values = []
					for sev in ("高", "中", "低", "情報"):
						if sev in rawdata:
							values.extend(rawdata[sev])
					results.append({"top_domain" : "トップドメイン:{}".format(
													top_domain),
									"header"     : headers,
									"fields"     : values } )
				_data["digitalrisk"]["vuln_domain"]["results"] = results

			else:
				_data["digitalrisk"]["vuln_domain"]["results"] = None


		def _set_hunting_result(_data):
			def _parse_each_xml(each):
				root = ET.parse(each)
				summary = root.find("summary").text.strip()
				#num = root.find("detected_number").text.strip()
				num = root.find("detect_number").text.strip()
				recommendation = root.find("recommendation").text.strip()
				return [ summary, num, recommendation ]

			values = []
			_dir = "{}/userdata/{}/hunting".format(
				self.DATA_DIR, self.customer_name)
			if self.language == "english":
				_dir += "/en"
			_dir += "/*.xml"
			resultsfile = glob.glob(_dir)
			resultsfile.sort()
			for each in resultsfile:
				try:
					value = _parse_each_xml(each)
					values.append( value )
				except Exception as e:
					logger.warning("xml parse error {}".format(each))
					logger.exception(e)
			hdrs = [ each["name"] for each in _data["tableformat"]["hunting"]["column"] ]
			_data["threat_hunting"]["results"] = {
					"header" : hdrs, "fields" :values }

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

		def _set_conclusion(_data):
			_data["userdata"]["conclusion"] = {
				"total_alert" : _data["alertdata"]["alert_num"],
				"incident" : len(_data["alertdata"]["incident_table"]["fields"]) }

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
		_set_agent_release(_data)
		_set_security_news(_data)
		_data["appendix"] = {}

		_sec = _data["headers"]["sections"]
		_huntconf = self.config.get("hunting")
		if _huntconf and not _huntconf.get("ioc_search"):
			_data["threat_hunting"]["enable"] = False
			correction_chapter(_sec["threat_hunting"]["number"], _sec)
		else:
			_data["threat_hunting"]["enable"] = True
			_set_hunting_result(_data)
			_set_table( _data["threat_hunting"]["results"], [2] )

		if _huntconf and _huntconf.get("digitalrisk"):
			_data["digitalrisk"]["enable"] = True
			_set_digitalrisk_monitor_target_result(_data)
			_set_table( _data["digitalrisk"]["monitor_target"]["results"], [1] )
			_set_digitalrisk_vuln_domain_result(_data)
			if _data["digitalrisk"]["vuln_domain"]["results"]:
				table = _data["digitalrisk"]["vuln_domain"]["description"]["rawtable"]
				_data["digitalrisk"]["vuln_domain"]["description"]["fields"] = [
						[ each["name"], each["content"] ] for each in table ]
				_set_table( _data["digitalrisk"]["vuln_domain"]["description"], [1] )
				for each in _data["digitalrisk"]["vuln_domain"]["results"]:
					_set_table( each, [0,1,2,3] )
			_set_digitalrisk_vuln_ipaddr_result(_data)
			if _data["digitalrisk"]["vuln_ipaddr"]["results"]:
				for each in _data["digitalrisk"]["vuln_ipaddr"]["results"]:
					_set_table( each, [] )
			_set_digitalrisk_impersonate_domain_result(_data)
			if _data["digitalrisk"]["impersonate_domain"]["results"]:
				for each in _data["digitalrisk"]["impersonate_domain"]["results"]:
					_set_table( each, [] )
			_set_digitalrisk_dataleak_result(_data)
			if _data["digitalrisk"]["dataleak"]["results"]:
				for each in _data["digitalrisk"]["dataleak"]["results"]:
					_set_table( each, [1] )
		else:
			_data["digitalrisk"]["enable"] = False
			correction_chapter(_sec["digitalrisk"]["number"], _sec)

		_otherconf = self.config.get("other")
		if _otherconf and _otherconf.get("config_history"):
			_data["config_history"]["enable"] = True
			_set_config_history_result(_data)
			_set_table( _data["config_history"]["results"], [2] )
		else:
			_data["config_history"]["enable"] = False
			correction_chapter(_sec["config_history"]["number"], _sec)

		_set_table( _data["software_release"]["server_release"]["table"], [] )
		_set_table( _data["software_release"]["agent_release"]["table"], [] )
		_data["alertdata"] = {}
		alertnum = 0
		alertnum_6month = 0
		for each in tableinfo["severity_table"]["fields"]:
			alertnum += each[1]
		for each in tableinfo["monthlychart_table"]["fields"]:
			alertnum_6month += each[1]
		_set_table( tableinfo["severity_table"],     [2]   )
		_set_table( tableinfo["dailychart_table"],   [0]   )
		_set_table( tableinfo["monthlychart_table"], [0]   )
		_set_table( tableinfo["malware_table"],      [0,3] )
		_set_table( tableinfo["host_table"],         [0]   )
		_set_table( tableinfo["os_table"],           [0]   )
		_set_table( tableinfo["incident_table"],     []    )
		_data["alertdata"]["alert_num"] = alertnum
		_data["alertdata"]["alert_num_6month"] = alertnum_6month
		_data["alertdata"].update(tableinfo)
		_data["userdata"] = { "comments" : [], "conclusion" : None }
		_set_other_comment(_data)
		_set_conclusion(_data)

