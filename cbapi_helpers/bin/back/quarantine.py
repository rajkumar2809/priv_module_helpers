# -*- coding: utf-8 -*-

import sys, os
import argparse
from priv_module_helpers.cbapi_helpers import cb_api_helper as api
from monkey_tools.utils import logger_util

import logging

reload(sys)
sys.setdefaultencoding("utf-8")

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/.."
sys.path.append(PJ_TOP)
CONF_DIR  = PJ_TOP+"/config"
LOG_DIR   = PJ_TOP+"/log"
_LOG_CONF = CONF_DIR+"/log/quarantine.conf"

def get_exapi(customer_info):
	return api.init_by_cfg_file(customer_info, "ex")

parser = argparse.ArgumentParser(description="send message command by live response")
parser.add_argument('customer_name', help="customer name of dhsoc splunk config")
parser.add_argument('device_id', help="device id for send command")
parser.add_argument('-quarantine', default="ON",
		choices=["ON","OFF"], help="quarantine or unquarantine")
args = parser.parse_args()
customer_name = args.customer_name
device_id = args.device_id
if args.quarantine == "ON":
	quarantine_on = True
else:
	quarantine_on = False

def main(logger):
	logger.info("start quarantine device.")
	logger.info("get api module for {}".format(customer_name))
	api = get_exapi(customer_name)
	logger.info("quarantine targetId:{}".format(device_id))
	if quarantine_on:
		flag = api.quarantine(device_id)
	else:
		flag = api.unquarantine(device_id)
	logger.info("finish to send command. result:{}".format(flag))
	if flag:
		print 0
	else:
		print 1

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("quarantine")
	logging.getLoggerClass().root.handlers[0].baseFilename
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main(logger)
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

