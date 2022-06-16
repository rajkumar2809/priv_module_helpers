# -*- encoding:utf-8

import os, sys
import json
import argparse

from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

_COMMAND_DESC_ = "pull ticketInfo from redmine to splunk."

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
MODULE_DIR = CURR_DIR+"/../"
LOG_DIR   = MODULE_DIR+"/log"
CONF_DIR  = MODULE_DIR+"/config"
_LOG_CONF = CONF_DIR+"/log.conf"
CONF_FILE = CONF_DIR+"/config.json"

sys.path.append(MODULE_DIR)

import rm_sync

def _set_cli():
	parser = argparse.ArgumentParser(
			description=_COMMAND_DESC_)
	parser.add_argument('product', 
			help="product for change comment.")
	parser.add_argument('target', 
			default=None, help="alert_id or csv.gz file name for target alert.")
	parser.add_argument('--by_file', '-f',
			nargs="?", const=True, help="get target by csv.gz file.")
	parser.add_argument('--by_local',
			nargs="?", const=True, help="use localhost splunk.")
	parser.add_argument('--with_ioc', '-i',
			nargs="?", const=True, help="send IOC info to splunk.")
	return parser.parse_args()

objects = {
	rm_sync.RedMineSync4Stellar._PRODUCT_   : rm_sync.RedMineSync4Stellar,
	rm_sync.RedMineSync4Helix._PRODUCT_     : rm_sync.RedMineSync4Helix,
	rm_sync.RedMineSync4CBDefense._PRODUCT_ : rm_sync.RedMineSync4CBDefense
}

def main():
	args = _set_cli()
	logger.info("start command: {}".format(_COMMAND_DESC_))
	rmsync = objects[args.product](args.target, args.by_file, args.by_local)
	logger.info("check redmine")
	rmsync.check_redmine()
	logger.info("post log to splunk if updated.")
	rmsync.postall2splunk()
	if args.with_ioc:
		logger.info("post Hash base IOC to splunk.")
		hashinfo_list = rmsync.get_regitered_hashinfo()
		if len(hashinfo_list) is not 0:
			rmsync.send_feedback(hashinfo_list, False)
	logger_util.change_permission_log_file(LOG_DIR)

if __name__ == "__main__":
	os.chdir(MODULE_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("check_analyst_result")
	rm_sync.logger = logger
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)

