# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import requests
import argparse, json

reload(sys)
sys.setdefaultencoding("utf-8")

from monkey_tools.utils import logger_util

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_CONF_PATH = CURR_DIR+"/config"
_LOG_CONF = _CONF_PATH+"/log.conf"
_APP_NAME = "postcsv2mickyapp"
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
_REG_TYPE = {
	"false_positive" : "FalsePositive/Register.php",
	"low_alert" : "LowAlert/Register.php"
}

_URL_TOP = {
	"test" : "mkaneko",
	"production" : "dhsoc"
}

TOP_HELP ='''
Post Alert List to MickyApp.
ex1) no args is send to localhost(test environment) with false_positive
	python upload2mickyapp.py
ex2) send to production environment(dhsoc).
	python upload2mickyapp.py --app_type=production
ex3) send to production environment(dhsoc) with another host.
	python upload2mickyapp.py --app_type=production --server=splunk00
ex4) send low alert list.
	python upload2mickyapp.py --app_type=production --server=splunk00 --register_type=low_alert
'''

parser = argparse.ArgumentParser(description=TOP_HELP)

_FIELD = 'csvfile'

def _set_argement():
	parser.add_argument('file_name', help="send alert list by csv file.")
	parser.add_argument('--server',
			choices=_SERVER.keys(),
			default=None,
			help="Post Server Target. if you not set this, post to localhost.")
	parser.add_argument('--register_type',
			choices=_REG_TYPE.keys(),
			default="false_positive",
			help="Register Data Type. if you not set this, reg by false positive.")
	parser.add_argument('--app_type',
			choices=_URL_TOP.keys(),
			default="test",
			help="Choise Application Env. if you not set this, test env.")

def _get_hostname():
	return os.uname()[1]

def _get_url(svr_name, reg_type, app_type):
	if svr_name:
		webhost = _SERVER[svr_name]
	else:
		webhost = _get_hostname()
	return "https://{}/{}/{}".format( webhost,
		_URL_TOP[app_type], _REG_TYPE[reg_type] )

def main():
	_set_argement()
	args = parser.parse_args()
	fileDataBinary = open(args.file_name, "rb").read()
	logger.debug("data size is :{}".format(len(fileDataBinary)))
	files = {_FIELD : (args.file_name, fileDataBinary, "text/csv")}
	url = _get_url(args.server, args.register_type, args.app_type)
	logger.debug("URL is :{}".format(url))
	response = requests.post(url, files=files, verify=False)
	logger.debug("ResPonseCode is :{}".format(response.status_code))
	if response.status_code == 200:
		print 0
		logger.info("successfully post csv.")
	else:
		print 1
		logger.info("failed to post csv.")
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

