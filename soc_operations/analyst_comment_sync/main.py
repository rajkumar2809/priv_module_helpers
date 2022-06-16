# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import requests
import argparse, json

reload(sys)
sys.setdefaultencoding("utf-8")

from monkey_tools.utils import logger_util, file_util
from priv_module_helpers.redmine_helpers import util as _rm
from priv_module_helpers.splunk_helpers.splunk_post_helper import SplunkLogSender

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_CONF_PATH = CURR_DIR+"/config"
_CONF_FILE = _CONF_PATH+"/config.json"
_LOG_CONF = _CONF_PATH+"/log.conf"
_APP_NAME = "analystchecker"
LOG_DIR   = CURR_DIR+"/log"

logger_util.init_conf(_LOG_CONF)
logger = logger_util.get_standard_logger(_APP_NAME)

_SERVER = {
	"license01" : "splunk-license01.dhsoc.jp",
	"splunk00" : "splunk-production00.dhsoc.jp",
	"splunk01" : "splunk-production01.dhsoc.jp",
	"splunk02" : "splunk-production02.dhsoc.jp",
	"splunk03" : "mickyapp03.dhsoc.jp",
	"splunk04" : "mickyapp04.dhsoc.jp",
	"localhost" : "localhost"
}

TOP_HELP ='''
Check Analyst comment and post info tu splunk.
ex1) no args is send to localhost(test environment) with false_positive
	python main.py filename_of_alerts.csv.gz
ex2) send to production environment(dhsoc).
	python main.py filename_of_alerts.csv.gz --server=splunk00
'''

parser = argparse.ArgumentParser(description=TOP_HELP)


def _set_argement():
	parser.add_argument('file_name', help="send alert list by csv file.")
	parser.add_argument('--server',
			choices=_SERVER.keys(),
			default="localhost",
			help="Post Server Target. if you not set this, post to localhost.")

def _get_ticket_list(splunk_server, fpcheck_results):
	idlist = []
	for each in fpcheck_results:
		try:
			idlist.append( int(each["ticket_id"]) )
		except Exception as e:
			logger.error("Error occurred Data is : {}".format(each) )
			logger.exception(e)
	return _rm.get_ticket_infos(splunk_server, idlist, False)

def _update_analyze_result(fpcheck_result, splunk_server, cfg, tickets):
	info = json.loads(fpcheck_result["_raw"])
	_id = info["ticket_id"]
	if _id in tickets and tickets[_id]:
		ticket_info = tickets[_id]
		info["analyst_comment"] = ticket_info["message"]
		info["ticket_status"] = ticket_info["status"]
		info["correct_severity"] = ticket_info["severity"]
		info["product"] = fpcheck_result.get("product")
		data = json.dumps(info)
		if info["ticket_status"] in ("1次終了", "2次終了", "品質確認"):
			post_splunk_log( data, _id, cfg["splunk"]["post"], splunk_server )

def post_splunk_log( data, ticket_id, sp_conf, splunk_server ):
	splunk = SplunkLogSender(
			splunk_server, sp_conf["username"], sp_conf["password"])
	logger.info("post incident of {} to {}".format(ticket_id, splunk_server))
	splunk.init_params(_APP_NAME, sp_conf["index"], sp_conf["source"], sp_conf["sourcetype"])
	hdr = {"Content-Type": "application/json"}
	splunk.post_data(_APP_NAME, data, headers=hdr)

def main():
	_set_argement()
	args = parser.parse_args()
	with open(_CONF_FILE) as f:
		cfg = json.load(f)
	splunk_server = _SERVER[args.server]
	fpcheck_results = file_util.parse_csv_gzip(args.file_name)
	tickets = _get_ticket_list(splunk_server, fpcheck_results)
	for each in fpcheck_results:
		try:
			_update_analyze_result(each, splunk_server, cfg, tickets)
		except Exception as e:
			logger.exception(e)
	os.remove( args.file_name )

if __name__ == '__main__':
	logger.info("start")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main()
	except Exception as e:
		logger.critical(e.message)
		logger.exception(e)
	logger.info("end")

