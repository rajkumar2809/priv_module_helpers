# -*- coding: utf-8 -*-

import sys, os
import json
import argparse
from priv_module_helpers.cbapi_helpers.v6_api import cb_api_helper as _api
from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

MAX_RETRY = 3

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/.."
sys.path.append(PJ_TOP)
CONF_DIR  = PJ_TOP+"/config"
LOG_DIR   = PJ_TOP+"/log"
_LOG_CONF = CONF_DIR+"/log/search_ioc.conf"

def get_api(customer_info):
	return _api.init_by_cfg_file(customer_info)

parser = argparse.ArgumentParser(description="search device by IOC(sha256).")
parser.add_argument('customer_name', help="searched customer name.")
parser.add_argument('hash_sha256', help="searched sha256 hash.")
args = parser.parse_args()
hash_sha256 = args.hash_sha256
customer_name = args.customer_name

def main(logger):
	logger.info("start script.")
	logger.info("get api module for {}".format(customer_name))
	api = get_api(customer_name)
	flag = False
	for i in range(0, MAX_RETRY):
		try:
			_raw = api.get_events(hash_sha256=hash_sha256, search_window="2w", rows=10000)
			devices = []
			for each in _raw:
				hostname = each["device_name"]
				if not hostname in devices:
					devices.append(hostname)
			print json.dumps({ "devices" : devices })
			flag = True
			logger.info("successfully search sha256 IOC. Qty:{}".format(len(_raw)))
			break
		except IOError as e:
			logger.error("error occurred {} times".format(i))
			logger.exception(e)
	assert flag, "cannot access to CBDefense!"

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

