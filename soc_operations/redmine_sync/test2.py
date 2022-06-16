# -*- encoding:utf-8

import os, sys
import json
import argparse

from monkey_tools.utils import file_util
from monkey_tools.utils import time_util
from monkey_tools.utils import logger_util

from priv_module_helpers.redmine_helpers import rm_helpers as rmh
from priv_module_helpers.splunk_helpers.splunk_post_helper import SplunkLogSender

reload(sys)
sys.setdefaultencoding("utf-8")

_COMMAND_DESC_ = "pull ticketInfo from redmine to splunk."

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR  = CURR_DIR+"/config"
#GZIPDIR   = CURR_DIR+"/testdata"
_LOG_CONF = CONF_DIR+"/log.conf"
CONF_FILE = CONF_DIR+"/config.json"

class RedMineSync(object):

	_FLAGS_ = [
		"*result*",
		"*analyze_result*"
	]
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
			if result["status"] == "新規":
				return False
			elif "ticket_updated" in alert:
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
		severity_cfid = cfid["risk_level"]
		logger.info("ticket is existing. ID:{}".format(ticket["id"]))
		result = {  "alert_id"  : alert_id,
					"ticket_id" : ticket["id"],
					"updated"   : ticket["updated"],
					"status"    : ticket["status"] }
		for cf in ticket["custom_fields"]:
			if cf["id"] == severity_cfid:
				result["severity"] = cf["value"]
		result["notes"] = []
		result["analyst_comment"] = []
		for each in ticket["notes"]:
			note = each["note"]
			for each_flag in self._FLAGS_:
				if note.startswith(each_flag):
					note = note.replace(each_flag, "").strip()
					result["analyst_comment"].append( {
							"date" : each["created"],
							"note" : note } )
					break
			flag = False
			for each_flag in self._SYSUPDATE_FLAG_:
				if note.startswith(each_flag) and len(note) is 0:
					flag = True
					break
			if not flag:
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

class RedMineSync4Stellar(RedMineSync):
	_PRODUCT_ = "stellar"

class RedMineSync4Helix(RedMineSync):
	_PRODUCT_ = "helix"

class RedMineSync4CBDefense(RedMineSync):
	_PRODUCT_ = "cbdefense"

	def _get_alert_id(self, alert):
		return alert["incident_id"]

def _set_cli():
	parser = argparse.ArgumentParser(
			description=_COMMAND_DESC_)
	parser.add_argument('product', 
			help="product for change comment.")
	parser.add_argument('target', 
			default=None, help="alert_id or csv.gz file name for target alert.")
	parser.add_argument('--customer_name', 
			default=None, help="customer name for change comment.")
	parser.add_argument('--by_file', '-f',
			nargs="?", const=True, help="get target by csv.gz file.")
	parser.add_argument('--by_local',
			nargs="?", const=True, help="use localhost splunk.")
	return parser.parse_args()

objects = {
	RedMineSync4Stellar._PRODUCT_   : RedMineSync4Stellar,
	RedMineSync4Helix._PRODUCT_     : RedMineSync4Helix,
	RedMineSync4CBDefense._PRODUCT_ : RedMineSync4CBDefense
}

def main():
	args = _set_cli()
	logger.info("start command: {}".format(_COMMAND_DESC_))
	rmsync = objects[args.product](args.target, args.by_file, args.by_local)
	logger.info("check redmine")
	rmsync.check_redmine()
	logger.info("post log to splunk if updated.")
	rmsync.postall2splunk()

if __name__ == "__main__":
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("check_analyst_result")
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)

