# -*- coding: utf-8 -*-

import os, sys
import json
import subprocess

import cfg_util
from monkey_tools.utils import logger_util
from monkey_tools.utils import rest_util

_PYTHON = '/usr/bin/python2.7'
_SCRIPT_NAME = "main.py"
logger = logger_util.get_standard_logger("riskchecker_booter")

def get_data_dir():
	cfg = cfg_util.parse_config()
	gzip_dir = cfg["gzip_dir"]
	logger.debug("get gzip dir:{}".format(gzip_dir))
	return gzip_dir

def get_script_dir():
	_dir = cfg_util.CURR_DIR
	logger.debug("get script dir:{}".format(_dir))
	return _dir

def boot():
	logger.info("boot script:{} python:{}".format(_SCRIPT_NAME, _PYTHON))
	_dir = get_script_dir()
	script = "{}/{}".format(_dir, _SCRIPT_NAME)
	os.chdir(_dir)
	sp=subprocess
	try:
		return sp.call([_PYTHON, script], stderr=sp.STDOUT)
	except sp.CalledProcessError as e:
		logger.error("call script is error. message:{}".format(e.output))
		logger.exception(e)
		return 1

def make_ticket_only(alert, splunk_server, severity):
	import rm_helper
	cfg = cfg_util.parse_config()
	rm_conf = cfg["redmine"]
	alert_id = alert["alert_summary"]["alert_id"]
	_fpresult = {   "flag"             : True,
					"is_gray"          : False,
					"correct_severity" : severity,
					"message"          : ["make by manual"] }
	rm_helper._issue_redmine_ticket(rm_conf, alert)
	id_list = rm_helper.get_ticket_idlist(rm_conf, alert_id)
	instruction_url = _get_instruction_url(id_list[0],  alert, splunk_server)
	rm_helper.update_redmine_ticket( rm_conf, id_list, alert, _fpresult,
		instruction_url, _need_tier1=True )

def _get_instruction_url(_id, alert, splunk_server):
	def get_process_list(process_info):
		if process_info:
			results = []
			for each in process_info:
				ps = each["process_info"]
				results.append("{}:{}".format(ps["path"], ps["hash"]))
			return ",".join(results)
		else:
			return ""

	def get_malware_list(malware_info):
		if malware_info:
			results = []
			for each in malware_info:
				name = ""
				app = each["applicationName"]
				virus = each["virusName"]
				catac = each["virusCategory"]
				subcatac = each["virusSubCategory"]
				if app and not app == "null":
					name = app
				elif virus and not virus == "null":
					name = virus
				elif subcatac and not subcatac == "null":
					name = subcatac
				else:
					name = catac
				results.append("{}:{}".format(name, each["sha256Hash"]))
			return ",".join(results)
		else:
			return ""

	def _severity_to_jpn(severity):
		severity = severity.lower()
		if severity == "high" or severity == u"高":
			return u"高"
		elif severity == "middle" or severity == u"中":
			return u"中"
		elif severity == "low" or severity == u"低":
			return u"低"
		else:
			return u"-"
	if splunk_server:
		if "production00" in splunk_server:
			splunk_server = "mickyapp00.sgw001.dhsoc.jp"
		elif "production02" in splunk_server:
			splunk_server = "mickyapp02.sgw001.dhsoc.jp"
		elif "production03" in splunk_server:
			splunk_server = "mickyapp03.sgw001.dhsoc.jp"
		elif "production04" in splunk_server:
			splunk_server = "mickyapp04.sgw001.dhsoc.jp"
		if "mickyapp00.sgw001" in splunk_server: #TODO
			url='https://'+splunk_server+'/dhsoc/Tier1/CustomerInstruction/'
		else:
			url='https://'+splunk_server+'/dhsoc/CustomerInstruction/'
	else:
		url='https://splunk_server_name/dhsoc/CustomerInstruction/'
	customer_name = alert["alert_src"]["customer_name"]
	if customer_name.startswith("NSL"):
		url=url+'instruction_2.php'
	else:
		url=url+'instruction.php'
	severity_jpn = _severity_to_jpn(alert["alert_summary"]["severity"])
	params = {
			"customer_id" : alert["alert_src"]["customer_name"],
			"severity" : severity_jpn,
			"alert_datetime" : alert["alert_summary"]["alert_time"],
			"policy" : alert["alert_detail"]["device_group"],
			"device_id" : alert["alert_detail"]["device_id"],
			"ticket_no" : str(_id),
			"alert_id" : alert["alert_summary"]["alert_id"],
			"device_name" : alert["alert_summary"]["hostname"],
			#"processes" : get_process_list(alert["alert_detail"]["threat_app_detail"]),
			"malwares" : get_malware_list(alert["alert_summary"]["malware_info"])
	}
	if customer_name.startswith("NSL"):
		params["type"]="CB"
	return rest_util.build_url(url, params=params)

