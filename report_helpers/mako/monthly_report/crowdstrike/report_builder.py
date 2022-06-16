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
		statsByOrigSev = alertinfo["statsByOrigSev"]
		sender_name = alertinfo["sender_name"]
		language = alertinfo["language"]
		formal_name = alertinfo["formal_name"]
		obj = cls(customer_name, formal_name, sender_name, tableinfo, alerts, statsByOrigSev, geninfo, language, alertinfo["user_config"])
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
		obj = cls(customer_name, formal_name, sender_name, None, alerts, None, geninfo, language, alertinfo["user_config"], make_html=False)
		obj.make_pdf()

	
	def __init__(self, customer_name, formal_name, sender_name, tableinfo, alerts, statsByOrigSev, geninfo, language, user_config, make_html=True):
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
			self._set_reportinfo(info, reportdata, tableinfo, statsByOrigSev)
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
		result = {"product" : "CrowdStrike Falcon"}
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

	def _set_reportinfo(self, info, _data, tableinfo, statsByOrigSev):
		def _set_target(info, _data):
			tgt = _data["report_target"]
			tgt["customer_name"] = self.formal_name
			tgt["report_month"] = info["report_month"]
			for each in tgt["table"]["contents"]:
				each["content"] = info[each["src"]]

		def _set_crowdstrike_originseverity(_data, statsByOrigSev):
			if self.language == "japanese":
				hdrs = [ "危険度", "アラート数" ]
			else:
				hdrs = [ "Severity", "Number of Alerts" ]
			fields = []
			for eachsev in [ "critical", "high", "medium", "low" ]:
				value = statsByOrigSev[eachsev] if eachsev in statsByOrigSev else 0
				fields.append( [ eachsev, str(value) ] )
			_data["appendix"]["statsByOrigSev"] = { "fields" : fields, "header" : hdrs }

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
			section = _data["agent_release"]
			updated = []
			hdrs = [ each["name"] for each in _data["tableformat"]["agent_release"]["column"] ]
			for each_os in section["versions"]:
				values = []
				if each_os["updated"]:
					updated.append( each_os["os"] )
				for each in each_os["supported"]:
					if each["version"] is None:
						each["version"] = ""
					if each["release_date"] is None:
						each["release_date"] = ""
					v = [   each["version"],      each["build"],
							each["release_date"], each["end_of_support"] ]
					values.append( v )
				if each_os["os"].lower() == "windows":
					table = {"table" : {"header" : hdrs, "fields" : values} }
					section["windows"] = table
				elif each_os["os"].lower() == "os x":
					table = {"table" : {"header" : hdrs, "fields" : values} }
					section["macos"] = table
				elif each_os["os"].lower() == "linux":
					table = {"table" : {"header" : hdrs, "fields" : values} }
					section["linux"] = table
			section["updated"] = updated
		
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

		def _parse_spotlight_data():
			results = []
			_dir = "{}/userdata/{}/spotlight/rawdata".format(
				self.DATA_DIR, self.customer_name)
			_dir += "/*.csv"
			for eachfile in glob.glob(_dir):
				each = file_util.parse_csv(eachfile)
				results.extend(each)
			return results

		def _grep_spotlight_by(spotlight_data, value, field="タイプ", is_not=False):
			value = value.lower()
			results = []
			for each in spotlight_data:
				hosttype = each[field].lower()
				if value in hosttype and not is_not:
					results.append(each)
				elif not value in hosttype and is_not:
					results.append(each)
			return results

		def _set_spotlight_by_client(_data, spotlight_data, limits=100):
			data = _grep_spotlight_by(spotlight_data, "workstation")
			ovhigh = _grep_spotlight_by(data, "critical", field="CS危険度")
			ovhigh.extend( _grep_spotlight_by(data, "high", field="CS危険度") )
			actives = _grep_spotlight_by(ovhigh, "悪用及びPOCコードの公開等なし", field="悪用状況", is_not=True)
			hdrs = [ each["name"].strip() for each in _data["tableformat"]["spotlight"]["activeVulnOverHigh"]["column"] ]
			_data["spotlight"]["client"]={ "total" : len(data) }
			if(len(data)>0):
				_data["spotlight"]["client"]["highest"] = str(_get_max_cvss_from_spotlight(data))
				fields = []
				num = 0
				limitover = False
				for each in actives:
					if num>limits:
						limitover = True
						break
					else:
						num += 1
					eachresult = []
					for _col in hdrs:
						_col = _col.encode("utf-8")
						eachresult.append(each.get(_col))
					fields.append(eachresult)
				_data["spotlight"]["client"]["actives"] = {
						"limitover" : limitover,
						"header" : hdrs, "fields" : fields }
				hdrs, fields  = _top_by_spotlight(ovhigh, "ホスト名", _data["tableformat"]["spotlight"]["manyhostsOverHigh"])
				_data["spotlight"]["client"]["groupby_host"] = {
						"header" : hdrs, "fields" : fields }
				hdrs, fields  = _top_by_spotlight(ovhigh, "検出対象", _data["tableformat"]["spotlight"]["manyappsOverHigh"])
				_data["spotlight"]["client"]["groupby_product"] = {
						"header" : hdrs, "fields" : fields }


		def _set_spotlight_by_server(_data, spotlight_data, limits=100):
			data = _grep_spotlight_by(spotlight_data, "server")
			ovhigh = _grep_spotlight_by(data, "critical", field="CS危険度")
			ovhigh.extend( _grep_spotlight_by(data, "high", field="CS危険度") )
			actives = _grep_spotlight_by(ovhigh, "悪用及びPOCコードの公開等なし", field="悪用状況", is_not=True)
			hdrs = [ each["name"].strip() for each in _data["tableformat"]["spotlight"]["activeVulnOverHigh"]["column"] ]
			_data["spotlight"]["server"]={ "total" : len(data) }
			if(len(data)>0):
				_data["spotlight"]["server"]["highest"] = str(_get_max_cvss_from_spotlight(data))
				fields = []
				num = 0
				limitover = False
				for each in actives:
					if num>limits:
						limitover = True
						break
					else:
						num += 1
					eachresult = []
					for _col in hdrs:
						_col = _col.encode("utf-8")
						eachresult.append(each.get(_col))
					fields.append(eachresult)
				_data["spotlight"]["server"]["actives"] = {
						"limitover" : limitover,
						"header" : hdrs, "fields" : fields }
				hdrs, fields  = _top_by_spotlight(ovhigh, "ホスト名", _data["tableformat"]["spotlight"]["manyhostsOverHigh"])
				_data["spotlight"]["server"]["groupby_host"] = {
						"header" : hdrs, "fields" : fields }
				hdrs, fields  = _top_by_spotlight(ovhigh, "検出対象", _data["tableformat"]["spotlight"]["manyappsOverHigh"])
				_data["spotlight"]["server"]["groupby_product"] = {
						"header" : hdrs, "fields" : fields }

		def _set_spotlight_by_domaincontroller(_data, spotlight_data, limits=100):
			data = _grep_spotlight_by(spotlight_data, "domain controller")
			ovhigh = _grep_spotlight_by(data, "critical", field="CS危険度")
			ovhigh.extend( _grep_spotlight_by(data, "high", field="CS危険度") )
			actives = _grep_spotlight_by(ovhigh, "悪用及びPOCコードの公開等なし", field="悪用状況", is_not=True)
			hdrs = [ each["name"].strip() for each in _data["tableformat"]["spotlight"]["activeVulnOverHigh"]["column"] ]
			_data["spotlight"]["domaincontroller"]={ "total" : len(data) }
			if(len(data)>0):
				_data["spotlight"]["domaincontroller"]["highest"] = str(_get_max_cvss_from_spotlight(data))
				fields = []
				num = 0
				limitover = False
				for each in actives:
					if num>limits:
						limitover = True
						break
					else:
						num += 1
					eachresult = []
					for _col in hdrs:
						_col = _col.encode("utf-8")
						eachresult.append(each.get(_col))
					fields.append(eachresult)
				_data["spotlight"]["domaincontroller"]["actives"] = {
						"limitover" : limitover,
						"header" : hdrs, "fields" : fields }

		def _top_by_spotlight(data, field, headers, limit=10):
			grouping = _grouping_from_spotlight(data, field)
			tmp = {}
			for groupcode, eachdata in grouping.items():
				evnum = len(eachdata)
				if evnum in tmp:
					tmp[evnum].append({ "name" : groupcode, "data" : eachdata })
				else:
					tmp[evnum] = [ { "name" : groupcode, "data" : eachdata } ]
			tmpkeys = tmp.keys()
			tmpkeys.sort()
			tmpkeys.reverse()
			fields = []
			hdrs = [ each["name"].strip() for each in headers["column"] ]
			for evnum in tmpkeys[0:limit-1]:
				if len(fields)>9:
					break
				grouped_data = tmp[evnum]
				for each in grouped_data:
					activenum = len(_grep_spotlight_by(each["data"], "悪用及びPOCコードの公開等なし", field="悪用状況", is_not=True))
					max_cvss = _get_max_cvss_from_spotlight(each["data"])
					fields.append( [ each["name"], evnum, activenum, max_cvss ] )
			return hdrs, fields

		def _grouping_from_spotlight(data, field):
			result = {}
			for each in data:
				value = each[field]
				if value in result:
					result[value].append(each)
				else:
					result[value] = [ each ]
			return result

		def _get_max_cvss_from_spotlight(data):
			value = 0.0
			cvss_str = "N/A"
			for each in data:
				cvss_score = float(each["CVSSスコア"])
				if cvss_score>value:
					value = cvss_score
					cvss_str = each["CVSS危険度"]
			return "{}({})".format(value, cvss_str)

		def _set_spotlight_grandsummary(_data, spotlight_data):
			hdrs = [ each["name"] for each in _data["tableformat"]["spotlight"]["grandsummary"]["column"] ]
			server = {  "critical" : 0, "high" : 0, "medium" : 0,
						"low" : 0, "unknown" : 0 }
			client = {  "critical" : 0, "high" : 0, "medium" : 0,
						"low" : 0, "unknown" : 0 }
			domcon = {  "critical" : 0, "high" : 0, "medium" : 0,
						"low" : 0, "unknown" : 0 }
			for each in spotlight_data:
				hosttype = each["タイプ"].lower()
				cs_severity = each["CS危険度"].lower()
				severity = each["CVSS危険度"].lower()
				if "workstation" in hosttype:
					if cs_severity in client:
						client[cs_severity] += 1
					elif severity in client:
						client[severity] += 1
				elif "server" in hosttype:
					if cs_severity in server:
						server[cs_severity] += 1
					elif severity in server:
						server[severity] += 1
				elif "domain controller" in hosttype:
					if cs_severity in domcon:
						domcon[cs_severity] += 1
					elif severity in domcon:
						domcon[severity] += 1
			fields = []
			total = 0
			for each in domcon.values():
				total += each
			fields.append([ "Domain Controller", total, domcon["critical"],
				domcon["high"], domcon["medium"], domcon["low"], domcon["unknown"] ])
			total = 0
			for each in server.values():
				total += each
			fields.append([ "Server", total, server["critical"],
				server["high"], server["medium"], server["low"], server["unknown"] ])
			total = 0
			for each in client.values():
				total += each
			fields.append([ "WorkStation", total, client["critical"],
				client["high"], client["medium"], client["low"], client["unknown"] ])
			_data["spotlight"]["grandsummary"] = {
					"header" : hdrs, "fields" : fields }

		#TODO to be deleted
		def _set_spotlight_comments(_data):
			def _parse_each_xml(each):
				root = ET.parse(each)
				summary = root.find("summary").text.strip()
				recommendation = root.find("recommendation").text.strip()
				hosts = root.find("detected_hosts").text.strip()
				return [ summary, recommendation, hosts ]

			values = []
			_dir = "{}/userdata/{}/spotlight".format(
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
			hdrs = [ each["name"] for each in _data["tableformat"]["spotlight"]["comments"]["column"] ]
			_data["spotlight"]["comments"] = {
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

		def _set_discover_result(_data):
			def _parse_each_xml(each):
				root = ET.parse(each)
				summary = root.find("summary").text.strip()
				recommendation = root.find("recommendation").text.strip()
				hosts = root.find("detected_hosts").text.strip()
				return [ summary, recommendation, hosts ]

			values = []
			_dir = "{}/userdata/{}/discover".format(
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
			hdrs = [ each["name"] for each in _data["tableformat"]["discover"]["column"] ]
			_data["discover"]["results"] = {
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
		_set_crowdstrike_originseverity(_data, statsByOrigSev)

		_sec = _data["headers"]["sections"]
		_huntconf = self.config.get("hunting")
		if _huntconf and not _huntconf.get("ioc_search"):
			_data["threat_hunting"]["enable"] = False
			correction_chapter(_sec["threat_hunting"]["number"], _sec)
		else:
			_data["threat_hunting"]["enable"] = True
			_set_hunting_result(_data)
			_set_table( _data["threat_hunting"]["results"], [2] )

		if _huntconf and _huntconf.get("discover"):
			_data["discover"]["enable"] = True
			_set_discover_result(_data)
			_set_table( _data["discover"]["results"], [0,1,2] )
		else:
			_data["discover"]["enable"] = False
			correction_chapter(_sec["discover"]["number"], _sec)

		if _huntconf and _huntconf.get("spotlight"):
			_data["spotlight"]["enable"] = True
			spotlight_data = _parse_spotlight_data()
			# make table for host type and severity
			_data["spotlight"]["exists"] = len(spotlight_data)>0
			_set_spotlight_grandsummary(_data, spotlight_data)
			_set_table( _data["spotlight"]["grandsummary"], [0] )
			# make table for host type and severity
			_set_spotlight_by_domaincontroller(_data, spotlight_data)
			if not _data["spotlight"]["domaincontroller"]["total"] == 0:
				if _data["spotlight"]["domaincontroller"].has_key("actives"):
					_set_table( _data["spotlight"]["domaincontroller"]["actives"], [] )
			# make table for host type and severity
			_set_spotlight_by_server(_data, spotlight_data)
			if not _data["spotlight"]["server"]["total"] == 0:
				if _data["spotlight"]["server"].has_key("actives"):
					_set_table( _data["spotlight"]["server"]["actives"], [] )
				_set_table( _data["spotlight"]["server"]["groupby_host"], [] )
				_set_table( _data["spotlight"]["server"]["groupby_product"], [] )
			# make table for host type and severity
			_set_spotlight_by_client(_data, spotlight_data)
			if not _data["spotlight"]["client"]["total"] == 0:
				if _data["spotlight"]["client"].has_key("actives"):
					_set_table( _data["spotlight"]["client"]["actives"], [] )
				_set_table( _data["spotlight"]["client"]["groupby_host"], [] )
				_set_table( _data["spotlight"]["client"]["groupby_product"], [] )
			_set_spotlight_comments(_data)
			_set_table( _data["spotlight"]["comments"], [0,1,2] )
		else:
			_data["spotlight"]["enable"] = False
			correction_chapter(_sec["spotlight"]["number"], _sec)

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
		_set_table( _data["appendix"]["statsByOrigSev"], [])

		_set_table( _data["agent_release"]["windows"]["table"], [] )
		_set_table( _data["agent_release"]["macos"]["table"],   [] )
		_set_table( _data["agent_release"]["linux"]["table"],   [] )
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

