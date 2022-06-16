# -*- encoding:utf-8

import os, sys
import json
import argparse
import time
from base64 import b64encode as enc64, b64decode as dec64

from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

_COMMAND_DESC_ = "call AutoRun DHSOC."

CURR_DIR   = os.path.dirname( os.path.abspath(__file__) )
MODULE_DIR = CURR_DIR+"/../"
LOG_DIR    = MODULE_DIR+"/log"
CONF_DIR   = MODULE_DIR+"/config"
_LOG_CONF  = CONF_DIR+"/auto_response.conf"
CONF_FILE  = CONF_DIR+"/config.json"

_WAIT_TIME_ = 15

sys.path.append(MODULE_DIR)

from connectors.micky_app_api import micky_api_ex as _api

_SPLUNK = {
	"splunk-license" : "splunk-license01.dhsoc.jp",
	"splunk00" : "splunk-production00.dhsoc.jp",
	"splunk01" : "splunk-production01.dhsoc.jp",
	"splunk02" : "splunk-production02.dhsoc.jp"
}

_API_TYPEs = {
	"call_ivr"   : None,
	"cbdefense"  : "cb",
	"nssol"      : "nsl",
	"stellar"    : "stellar",
	"fireeye_nx" : "nx"
}

def _set_cli():
	parser = argparse.ArgumentParser(
			description=_COMMAND_DESC_)
	parser.add_argument('customer_id',
			help="alert source customer_id.")
	parser.add_argument('--api_type',
			choices=_API_TYPEs.keys(),
			default="call_ivr",
			help="api type for micky app")
	parser.add_argument('-n', '--splunk', 
			choices=_SPLUNK.keys(),
			default=None,
			help="splunk name for access URL.")
	parser.add_argument('-d', '--data', 
			default=None,
			help="query parameter for tier1 URL. data type is json or json with base64")
	parser.add_argument('-b', '--base64', 
			action="store_true",
			help="base64 flag for data argument.")
	return parser.parse_args()

def _get_hostname():
	return os.uname()[1]

def _parse_call_params(data, is_base64):
	if is_base64:
		data = dec64(data)
	return json.loads(data)

def main():
	args = _set_cli()
	logger.info("start command: {}".format(_COMMAND_DESC_))
	if args.splunk:
		splunk_name = _SPLUNK[args.splunk]
	else:
		splunk_name = _get_hostname()
	api_type = _API_TYPEs[args.api_type]
	logger.info("called data< {} >".format(args.data))
	api = _api.MickyAppAPI(args.customer_id, splunk_name, api_type)
	if api_type:
		logger.info("call AutoTier1 URL. URI:{}".format(api.uri))
		data = _parse_call_params(args.data, args.base64)
		res = api.autorun(wait_time=_WAIT_TIME_, **data)
	else:
		logger.info("call IVR URL to SOC Team.")
		api.ivr_call(wait_time=_WAIT_TIME_)
	logger.info("waiting call at every {} sec.".format(_WAIT_TIME_))
	logger.info("end script.")
	print 0

if __name__ == "__main__":
	os.chdir(MODULE_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("auto run tier1 app")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

