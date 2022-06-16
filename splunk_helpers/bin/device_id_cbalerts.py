# -*- coding: utf-8 -*-

import sys, os
import json
import argparse
from priv_module_helpers.splunk_helpers import splunk_alert_searcher as _splunk
from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

MAX_RETRY = 3

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/.."
sys.path.append(PJ_TOP)
CONF_DIR  = PJ_TOP+"/config"
LOG_DIR   = PJ_TOP+"/log"
_LOG_CONF = CONF_DIR+"/log/device_id_cbalerts.conf"

parser = argparse.ArgumentParser(description="search deviceId by ip or hostname.")
parser.add_argument('customer_name', help="customer name of dhsoc splunk config")
parser.add_argument('device_id', help="device_id for searched alert.")
parser.add_argument('-timerange', default=None, help="Earliest Time of search[min]. default is 30min.")
parser.add_argument('-cfg_name', default=None, help="cfg name without ext(.json).")
args = parser.parse_args()
customer_name = args.customer_name
device_id = args.device_id
timerange = "-{}m@m".format(args.timerange) if args.timerange else "-30m@m"
if args.cfg_name:
	_splunk._CONF = "{}.json".format(args.cfg_name)

def main(logger):
	logger.info("start script.")
	splunk = _splunk.MyAlertSearcher
	splunk.init_splunk_by_cfg_file()
	index = "mdr_report_cbd"
	queries = {}
	queries["alert_src.customer_name"] = customer_name
	queries["alert_detail.device_id"] = device_id
	transform  = '| spath alert_detail.device_id'
	transform  = '| spath alert_src.customer_name'
	transform  = '| spath alert_summary.alert_id'
	transform  = '| spath alert_summary.severity'
	transform += '| rename '
	transform += '  alert_detail.device_id  as device_id'
	transform += '  alert_src.customer_name as customer_name'
	transform += '  alert_summary.severity as severity'
	transform += '  alert_summary.alert_id as alert_id'
	transform += '| dedup device_id'
	transform += '| eval detect_time=_time'
	transform += '| table detect_time, customer_name, device_id, severity, alert_id'
	flag = False
	for i in range(0, MAX_RETRY):
		try:
			_raw = splunk.search(queries, index, timerange, transform=transform)
			logger.info("take search result from splunk. Num:{}".format(len(_raw)))
			flag = True
			break
		except IOError as e:
			logger.error("error occurred {} times".format(i))
			logger.exception(e)
	assert flag, "cannot access to splunk!"
	results = []
	for each in _raw:
		row = dict(each)
		if "alert_id" in row:
			logger.debug("alertID is {}".format(row["alert_id"]))
		results.append(row)
	logger.info("correct result Num:{}".format(len(results)))
	print json.dumps(results, ensure_ascii=False)

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("rest_command")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main(logger)
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

