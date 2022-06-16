# -*- encoding:utf-8

import os, sys
import json
import argparse
from logging import getLogger

from monkey_tools.utils import file_util
from monkey_tools.utils import time_util

from priv_module_helpers.redmine_helpers import rm_helpers as rmh
from priv_module_helpers.splunk_helpers.splunk_post_helper import SplunkLogSender

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR  = CURR_DIR+"/config"
CONF_FILE = CONF_DIR+"/config.json"

logger = getLogger("redmine_sync")

class RedMineSync(object):

	_FLAGS_ = [
		"*result*",
		"*analyze_result*"
	]
	_REG_FLAGS_ = {
		"hash" : "*register_hash*"
	}
	_SYSUPDATE_FLAG_ = [
		"https://splunk-production",
		"過検知判定：",
		"アラート検知により対応を開始",
		"お客様への電話連絡",
		"お客様へアラート解析レポートを送信",
		"これをもって、本件対応を終了"
	]
	def __init__(self, target, by_file=False, by_local=True):
		assert self._PRODUCT_, "unknown product"
		if by_file:
			self.alerts = self._get_alertinfo_byfile(target)
		else:
			self.alerts = self._get_alertinfo_bysplunk(target)
		with open(CONF_FILE) as f:
			self.config = json.load(f)
		self.results = {}
		self.product = self._PRODUCT_
		self.by_local = by_local

	def check_redmine(self):
		for each in self.alerts:
			alert = dict(each)
			alert_id = self._get_alert_id(alert)
			splunk_name = self._get_splunk_name(alert)
			result = self.check_analyze_result(alert, splunk_name)
			self.results[alert_id] = result
	
	def postall2splunk(self):
		for each in self.alerts:
			alert = dict(each)
			alert_id = self._get_alert_id(alert)
			splunk_name = self._get_splunk_name(alert)
			result = self.results[alert_id]
			if result is None:
				continue
			elif result["is_update"]:
				logger.info("ticket:{} is updated.".format(result["ticket_id"]))
				self.post2splunk(alert, result, self.product, splunk_name)
			else:
				logger.info("ticket:{} is not updated.".format(result["ticket_id"]))

	def post2splunk(self, alert, check_result, product, splunk_name=None):
		assert product in self.config, "unknown product:{}".format(product)
		_conf = self.config[product]
		alert_id = self._get_alert_id(alert)
		severity = check_result["severity"]
		logger.info("post log to splunk. ID:{} current_severity:{}".format(alert_id, severity))
		splunk = SplunkLogSender.init_splunk_by_cfg_file(splunk_name, by_local=self.by_local)
		splunk.init_params( product,
				index=_conf["index"], source=_conf["source"])
		data = json.dumps(check_result)
		splunk.post_data(product, data)

	def parse_check_result(self, alert, ticket, cfid):
		def is_update_ticket(alert, result):
			if "ticket_updated" in alert:
				if len(alert["ticket_updated"]) is not 0:
					current_updated = time_util.get_unix(
							alert["ticket_updated"], "UNIX")
					new_updated = time_util.get_unix(
							result["updated"], "UNIX")
					return new_updated>current_updated
				else:
					return True
			else:
				return True

		alert_id = self._get_alert_id(alert)
		customer_name = self._get_customer_name(alert)
		severity_cfid = cfid["risk_level"]
		logger.info("ticket is existing. ID:{}".format(ticket["id"]))
		result = {  "alert_id"  : alert_id,
					"ticket_id" : ticket["id"],
					"updated"   : ticket["updated"],
					"status"    : ticket["status"],
					"customer_name" : customer_name }
		for cf in ticket["custom_fields"]:
			if cf["id"] == severity_cfid:
				result["severity"] = cf["value"]
		result["notes"] = []
		result["analyst_comment"] = []
		result["register"] = {}
		for each in ticket["notes"]:
			note = each["note"].strip()
			flag = False if len(note) is 0 else True
			if flag:
				for each_flag in self._FLAGS_:
					if note.startswith(each_flag):
						flag = False
						note = note.replace(each_flag, "").strip()
						result["analyst_comment"].append( {
								"date" : each["created"],
								"note" : note } )
						break
			if flag:
				for reg_type, each_flag in self._REG_FLAGS_.items():
					if note.startswith(each_flag):
						flag = False
						note = note.replace(each_flag, "").strip()
						result["register"][reg_type] = note
			if flag:
				for each_flag in self._SYSUPDATE_FLAG_:
					if note.startswith(each_flag):
						flag = False
						break
			if flag:
				result["notes"].append( {
					"date" : each["created"],
					"note" : note } )

		result["is_update"] = is_update_ticket(alert, result)
		return result

	def check_analyze_result(self, alert,  splunk_name):
		alert_id = self._get_alert_id(alert)
		logger.info("check alert for ID:{}".format(alert_id))
		_rm = self._get_redmine_helper(splunk_name)
		cfid = _rm.get_cfid()
		alert_cfid = cfid["incident_id"]
		filters = { alert_cfid : alert_id }
		tickets = _rm.get_ticket_list(filters, "*")
		latest = 0
		ticket = None
		for each in tickets:
			updated = time_util.get_unix(each["updated"], "UNIX")
			if latest<updated:
				latest=updated
				ticket=each
		if ticket:
			return self.parse_check_result(alert, ticket, cfid)
		else:
			logger.info("ticket is not existing.")
			return None

	def get_regitered_hashinfo(self):
		results = []
		for each in [ each for each in self.results.values()
					if "hash" in each["register"] ]:
			results.append( {
				"analyst"   : each["analyst_comment"],
				"hash"      : each["register"]["hash"],
				"ticket_id" : each["ticket_id"],
				"severity"  : each["severity"],
				"alert_id"  : each["alert_id"],
				"customer_name" : each["customer_name"] } )
		return results
	
	def send_feedback(self, hashinfo_list, by_local=True):
		sphost = self.config["ioc_splunk"]["host"]
		index  = self.config["ioc_splunk"]["hash"]["index"]
		source = self.config["ioc_splunk"]["hash"]["source"]
		splunk = SplunkLogSender.init_splunk_by_cfg_file(sphost, by_local=by_local)
		for each in hashinfo_list:
			splunk.init_params( "ioc", index=index, source=source)
			data = json.dumps(each)
			splunk.post_data("ioc", data)

	def _get_alertinfo_byfile(self, filename):
		logger.info("get alert info by gzip file.")
		return file_util.parse_csv_gzip(filename)

	def _get_alertinfo_bysplunk(self, alert_id):
		logger.info("get alert info by splunk.")
		alerts = []
		#TODO not yet implemented.
		return alerts

	def _get_splunk_name(self, alert):
		if "splunk_server" in alert:
			return alert["splunk_server"] 
		else:
			logger.warning("splunk name is not existing in alert")
			return None

	def _get_redmine_helper(self, splunk_name):
		return rmh.RmHelper.init_for(splunk_name, self.product, by_local=self.by_local)

	def _get_alert_id(self, alert):
		return alert["alert_id"]

	def _get_customer_name(self, alert):
		return alert["customer_name"]

class RedMineSync4Stellar(RedMineSync):
	_PRODUCT_ = "stellar"

class RedMineSync4Helix(RedMineSync):
	_PRODUCT_ = "helix"

class RedMineSync4CBDefense(RedMineSync):
	_PRODUCT_ = "cbdefense"

	def _get_alert_id(self, alert):
		return alert["incident_id"]

