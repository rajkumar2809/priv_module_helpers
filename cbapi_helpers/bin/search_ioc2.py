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
_LOG_CONF = CONF_DIR+"/log/search_ioc2.conf"

def get_api(customer_info):
	return _api.init_by_cfg_file(customer_info)

parser = argparse.ArgumentParser(description="search device by IOC(sha256).")
parser.add_argument('customer_name', help="searched customer name.")
parser.add_argument('query', help="searched customer query.")
parser.add_argument('-search_days', help="searched time range(by days)[1-30].",
		default="1")
parser.add_argument('-rows', help="return max rows[1-1000].",
		default="100")
parser.add_argument('--detail',
	nargs="?", const=True, 
	help='with detail event info or not.') 
parser.add_argument('--format',
	nargs="?", const=True, 
	help='return by formatted json') 
args = parser.parse_args()
query = args.query
search_days = int(args.search_days)
rows = int(args.rows)
by_detail = args.detail
by_format = args.format
assert 0<search_days and search_days<31, "searchdays accept range is 1-30"
assert 1<rows and rows<1000, "rows accept range is 1-1000"
customer_name = args.customer_name

def main(logger):
	logger.info("start script.")
	logger.info("get api module for {}".format(customer_name))
	api = get_api(customer_name)
	flag = False
	for i in range(0, MAX_RETRY):
		try:
			logger.info("search by cusomer:{} query:[{}] ".format(
				customer_name, query))
			_raw = api.search(  query=query,
								search_window="{}d".format(search_days),
								rows = rows, is_detail=by_detail)
			if by_format:
				print json.dumps(_raw, indent=4)
			else:
				print json.dumps(_raw)
			flag = True
			logger.info("successfully search custom query. Qty:{}".format(len(_raw)))
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

