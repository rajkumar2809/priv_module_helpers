# -*- encoding:utf-8

import os, sys
import json
import argparse

from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

_COMMAND_DESC_ = "pull ioc from cyfirma to splunk."

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
MODULE_DIR = CURR_DIR+"/../"
LOG_DIR   = MODULE_DIR+"/log"
CONF_DIR  = MODULE_DIR+"/config"
_LOG_CONF = CONF_DIR+"/log.conf"
CONF_FILE = CONF_DIR+"/config.json"

sys.path.append(MODULE_DIR)

import cap_sync

_SPLUNK = {
	"splunk-license" : "splunk-production02",
	"splunk00" : "splunk-production00",
	"splunk01" : "splunk-production01",
	"splunk02" : "splunk-production02",
	"localhost" : "splunk"
}

def _set_cli():
	parser = argparse.ArgumentParser(
			description=_COMMAND_DESC_)
	parser.add_argument('--by_local', '-l',
			nargs="?", const=True, help="post ioc to local or remote splunk.")
	parser.add_argument('--by_all', '-a',
			nargs="?", const=True, help="by all cap user or not.")
	parser.add_argument('--by_diff', '-d',
			nargs="?", const=True, help="by diff at prev call or get current 24 hours ioc.")
	return parser.parse_args()

def main():
	args = _set_cli()
	logger.info("start command: {}".format(_COMMAND_DESC_))
	_sync = cap_sync.CyfirmaSync(by_local=args.by_local)
	logger.info("get ioc from cyfirma.")
	iocs = _sync.get_ioc( by_diff=args.by_diff, by_all=args.by_all )
	if iocs and len(iocs) is 0:
		logger.info("IOC information is not updated.")
	else:
		logger.info("post to splunk. IOC Num:{}".format(len(iocs)))
		for each in iocs:
			_sync.post2splunk(each)
	logger.info("end command.")

if __name__ == "__main__":
	os.chdir(MODULE_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("get_ioc_cyfirma")
	logger_util.change_permission_log_file(LOG_DIR)
	cap_sync.logger = logger
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)

