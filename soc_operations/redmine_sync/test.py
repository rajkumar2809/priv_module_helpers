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

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR  = CURR_DIR+"/config"
GZIPDIR   = CURR_DIR+"/testdata"
GZIP      = GZIPDIR+"/stellar.csv.gz"
_LOG_CONF = CONF_DIR+"/log.conf"
_PRODUCT_ = "stellar"

_SPLUNK_PARAM_ = {
	"index"  : "redmine_"+_PRODUCT_,
	"source" : "redmine"
}
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

def post2splunk(alert, check_result, splunk_name=None):
	alert_id = alert["alert_id"]
	severity = check_result["severity"]
	logger.info("post log to splunk. ID:{} current_severity:{}".format(alert_id, severity))
	splunk = SplunkLogSender.init_splunk_by_cfg_file(splunk_name, by_local=False)
	splunk.init_params(_PRODUCT_, **_SPLUNK_PARAM_)
	data = json.dumps(check_result)
	splunk.post_data(_PRODUCT_, data)

def parse_check_result(alert, ticket, cfid):
	def is_change_severity(alert, result):
		if "severity" in result:
			if alert["risklevel"].lower() == "low":
				return not result["severity"] == "低"
			elif alert["risklevel"].lower() == "middle":
				return not result["severity"] == "中"
			elif alert["risklevel"].lower() == "high":
				return not result["severity"] == "高"
			else:
				return False
		else:
			return False

	alert_id = alert["alert_id"]
	severity_cfid = cfid["risk_level"]
	logger.info("ticket is existing. ID:{}".format(ticket["id"]))
	result = {  "alert_id"  : alert_id,
				"ticket_id" : ticket["id"],
				"status"    : ticket["status"] }
	for cf in ticket["custom_fields"]:
		if cf["id"] == severity_cfid:
			result["severity"] = cf["value"]
	result["notes"] = []
	result["analyst_comment"] = []
	for each in ticket["notes"]:
		note = each["note"]
		for each_flag in _FLAGS_:
			if note.startswith(each_flag):
				note = note.replace(each_flag, "").strip()
				result["analyst_comment"].append( {
						"date" : each["created"],
						"note" : note } )
				break
		flag = False
		for each_flag in _SYSUPDATE_FLAG_:
			if note.startswith(each_flag) and len(note) is 0:
				flag = True
				break
		if not flag:
			result["notes"].append( {
				"date" : each["created"],
				"note" : note } )

	if is_change_severity(alert, result):
		result["is_update"] = True
	elif len(result["notes"]) is not 0:
		result["is_update"] = True
	else:
		result["is_update"] = False
	return result

def check_analyze_result(alert, splunk_name):
	alert_id = alert["alert_id"]
	logger.info("check alert for ID:{}".format(alert_id))
	_rm = rmh.init_for_stellar(splunk_name, by_local=False)
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
		return parse_check_result(alert, ticket, cfid)
	else:
		logger.info("ticket is not existing.")
		return None

def set_cli():
	parser = argparse.ArgumentParser(description="add analyst comment to redmine and splunk.")
	parser.add_argument('product', help="product for change comment.")
	parser.add_argument('customer_name', help="customer name for change comment.")
	parser.add_argument('alert_id', help="alert_id for change target alert id.")
	parser.add_argument('--splunk', default=None, help="post comment to splunk")
	parser.add_argument('--redmine', default=None, help="post comment to redmine")
	parser.add_argument('--severity', '-s', default=None, help="Earliest Time of search[min]. default is 30min.")
	parser.add_argument('--comment', '-c', default=None, help="cfg name without ext(.json).")

def main():
	data = file_util.parse_csv_gzip(GZIP)
	for each in data:
		alert = dict(each)
		splunk_name = alert["splunk_server"] if "splunk_server" in alert else None
		result = check_analyze_result(alert, splunk_name)
		if result["is_update"]:
			logger.info("ticket is updated")
			post2splunk(alert, result, splunk_name)
		else:
			logger.info("ticket is not updated")

if __name__ == "__main__":
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("check_analyst_result")
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)

