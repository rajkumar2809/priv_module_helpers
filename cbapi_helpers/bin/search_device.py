# -*- coding: utf-8 -*-

import sys, os
import json
import argparse
from priv_module_helpers.cbapi_helpers.v6_api import cb_api_helper as api
from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

MAX_RETRY = 3

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/.."
sys.path.append(PJ_TOP)
CONF_DIR  = PJ_TOP+"/config"
LOG_DIR   = PJ_TOP+"/log"
_LOG_CONF = CONF_DIR+"/log/search_device.conf"

def get_api(customer_info):
	return api.init_by_cfg_file(customer_info)

parser = argparse.ArgumentParser(description="search deviceId by ip or hostname.")
parser.add_argument('customer_name', help="customer name of dhsoc splunk config")
parser.add_argument('-ipaddr', default=None, help="ip address for searched device.")
parser.add_argument('-hostname', default=None, help="hostname for searched device.")
args = parser.parse_args()
customer_name = args.customer_name
ipaddr = args.ipaddr
hostname   = args.hostname

def main(logger):
	logger.info("start script.")
	logger.info("get api module for {}".format(customer_name))
	api = get_api(customer_name)
	flag = False
	for i in range(0, MAX_RETRY):
		try:
			_raw = api.get_device_list(ip_addr=ipaddr, host_name=hostname)
			flag = True
			logger.info("successfully get device list. Qty:{}".format(len(_raw)))
			break
		except IOError as e:
			logger.error("error occurred {} times".format(i))
			logger.exception(e)
	assert flag, "cannot access to splunk!"
	results = [ {"device_id"   : each["device_id"],
				 "device_name" : each["hostname"],
				 "policy"      : each["policy"]   } for each in _raw ]
	print json.dumps(results)

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

