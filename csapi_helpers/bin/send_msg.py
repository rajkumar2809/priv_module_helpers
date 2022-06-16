# -*- coding: utf-8 -*-

import sys, os
import argparse
from priv_module_helpers.csapi_helpers import cs_api_helper as _api
from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/.."
sys.path.append(PJ_TOP)
CONF_DIR  = PJ_TOP+"/config"
LOG_DIR   = PJ_TOP+"/log"
_LOG_CONF = CONF_DIR+"/log/send_msg.conf"

def get_lrapi(customer_name):
	return _api.CSApiHelper4LiveResponse(customer_name)

#_TESTID_ = "9d29a22a692c40f98a7425e45930f6cd"

parser = argparse.ArgumentParser(description="send message command by live response")
parser.add_argument('customer_name', help="customer name of dhsoc splunk config")
parser.add_argument('device_id', help="device id for send command")
parser.add_argument('-script',
		default=None, help="device id for send command")
args = parser.parse_args()
customer_name = args.customer_name
device_id = args.device_id
script = args.script

def main(logger):
	logger.info("start send command")
	logger.info("get api module for {}".format(customer_name))
	api = get_lrapi(customer_name)
	logger.info("send to {}/{}".format(customer_name, device_id))
	flag = api.send_containment_message(device_id, script)
	logger.info("finish to send command. result:{}".format(flag))
	if flag:
		print 0
	else:
		print 1

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("live_response_command")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main(logger)
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

