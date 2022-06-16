# -*- encoding:utf-8

import os, sys
import json
import argparse
import time

from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

_COMMAND_DESC_ = "call IVR to DHSOC Team."

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
MODULE_DIR = CURR_DIR+"/../"
LOG_DIR   = MODULE_DIR+"/log"
CONF_DIR  = MODULE_DIR+"/config"
_LOG_CONF = CONF_DIR+"/call_ivr.conf"
CONF_FILE = CONF_DIR+"/config.json"

_WAIT_TIME_ = 15

sys.path.append(MODULE_DIR)

from connectors.micky_app_api import micky_api as _api

_SPLUNK = {
	"splunk-license" : "splunk-license01.dhsoc.jp",
	"splunk00" : "splunk-production00.dhsoc.jp",
	"splunk01" : "splunk-production01.dhsoc.jp",
	"splunk02" : "splunk-production02.dhsoc.jp"
}

def _set_cli():
	parser = argparse.ArgumentParser(
			description=_COMMAND_DESC_)
	parser.add_argument('customer_id',
			help="alert source customer_id.")
	parser.add_argument('-n', '--splunk', 
			choices=_SPLUNK.keys(),
			default=None,
			help="splunk name for access URL.")
	return parser.parse_args()

def _get_hostname():
	return os.uname()[1]

def main():
	args = _set_cli()
	user = os.environ.get("USER")
	logger.info("start command: {}, user:{}".format(_COMMAND_DESC_, user))
	if args.splunk:
		splunk_name = _SPLUNK[args.splunk]
	else:
		splunk_name = _get_hostname()
	api = _api.MickyAppAPI(args.customer_id, splunk_name)
	logger.info("call IVR.")
	result = api.ivr_call()
	time.sleep(_WAIT_TIME_)
	api.quit()
	logger.info("end script.")
	print 0

if __name__ == "__main__":
	os.chdir(MODULE_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("call_ivr")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

