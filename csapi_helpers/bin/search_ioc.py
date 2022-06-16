# -*- coding: utf-8 -*-

import sys, os, json
import argparse
from priv_module_helpers.csapi_helpers import cs_api_helper as _api
from monkey_tools.utils import logger_util

import logging

reload(sys)
sys.setdefaultencoding("utf-8")

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/.."
sys.path.append(PJ_TOP)
CONF_DIR  = PJ_TOP+"/config"
LOG_DIR   = PJ_TOP+"/log"
_LOG_CONF = CONF_DIR+"/log/search_ioc.conf"

def get_api(customer_info):
	return _api.CSApiHelper(customer_name)

parser = argparse.ArgumentParser(description="search device by IOC.")
parser.add_argument('customer_name', help="searched customer name.")
parser.add_argument('ioc_value', help="searched sha256 hash.")
parser.add_argument('-t', '--ioc_type', 
		choices=_api._SUPPORTED_IOCs,
		default="sha256",
		help="searched ioc type. default is sha256.")
args = parser.parse_args()
ioc_value = args.ioc_value
ioc_type  = args.ioc_type
customer_name = args.customer_name

def main(logger):
	logger.info("start to search ioc with {}[{}].".format(ioc_type, ioc_value))
	logger.info("get api module for {}".format(customer_name))
	api = get_api(customer_name)
	devices = api.search_devices_by_ioc(ioc_type, ioc_value)
	logger.info("finish to search ioc. result:{}".format(devices))
	print json.dumps({ "devices" : devices })

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("search_ioc")
	logging.getLoggerClass().root.handlers[0].baseFilename
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main(logger)
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

