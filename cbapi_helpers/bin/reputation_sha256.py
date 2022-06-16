# -*- coding: utf-8 -*-

import sys, os
import argparse
import json
from priv_module_helpers.cbapi_helpers.v6_api import cb_api_helper as api
from monkey_tools.utils import logger_util

import logging

reload(sys)
sys.setdefaultencoding("utf-8")

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/.."
sys.path.append(PJ_TOP)
CONF_DIR  = PJ_TOP+"/config"
LOG_DIR   = PJ_TOP+"/log"
_LOG_CONF = CONF_DIR+"/log/reputation_sha256.conf"

def get_api(customer_info):
	return api.init_by_cfg_file(customer_info, "rest")

parser = argparse.ArgumentParser(description="send message command by live response")
parser.add_argument('customer_name', help="customer name of dhsoc splunk config")
parser.add_argument('operation',
		choices=["add","delete", "search"], help="do which reputation op.")
parser.add_argument('-list_type', default=None,
		choices=["BLACK_LIST", "WHITE_LIST"], help="add which list of BLACK_LIST or WHITE_LIST")
parser.add_argument('sha256', help="target sha256 value")
parser.add_argument('-filename', default="unknown",
		help="filename of sha256 it is enable at add reputation.")
args = parser.parse_args()
customer_name = args.customer_name
_sha256 = args.sha256
_op = args.operation
_fname = args.filename
list_type = args.list_type

def main(logger):
	logger.info("start operation of reputation.")
	logger.info("get api module for {}".format(customer_name))
	api = get_api(customer_name)
	logger.info("{} sha256:{}.".format(_op, _sha256))
	if _op=="add" and list_type is None:
		logger.error("unset list_type of added reputation")
		return 1
	if list_type:
		res = api.reputation_sha256(_sha256, _op, list_type, _fname)
	else:
		res = api.reputation_sha256(_sha256, _op, filename=_fname)
	if _op == "search":
		data = json.dumps(res)
		logger.info("search result of sha256:{}".format(data))
		print data
	else:
		flag = res
		logger.info("finish to send command. result:{}".format(flag))
		if flag:
			print 0
		else:
			print 1

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("reputation_sha256")
	logging.getLoggerClass().root.handlers[0].baseFilename
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main(logger)
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

