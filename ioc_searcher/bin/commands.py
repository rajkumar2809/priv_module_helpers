#-*- encoding:utf-8 -*-

import os, sys, codecs
import argparse, base64, json

reload(sys)
sys.setdefaultencoding('utf-8')
sys.stdout = codecs.lookup('utf-8')[-1](sys.stdout)

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_DIR = CURR_DIR+"/.."
LOG_DIR   = MODULE_DIR+"/log"
CONF_DIR  = MODULE_DIR+"/config"
_LOG_CONF = CONF_DIR+"/commands.conf"
_GEN_CONF = CONF_DIR+"/config.json"
sys.path.append(MODULE_DIR)

from monkey_tools.utils import logger_util

import main as searcher
from products import fireeye_hx, cbdefense, crowdstrike

_SPLUNK = {
	"splunk-license" : "splunk-production02",
	"splunk00" : "splunk-production00",
	"splunk01" : "splunk-production01",
	"splunk02" : "splunk-production02",
	"localhost" : "splunk"
}

TOP_HELP ='''
check ioc for DHSOC MSS/MDR.
ex1) Note. default data_type is alert_id 
	python commands.py cbdefense
ex1a)
	python commands.py cbdefense --type=hash
ex2)
	python commands.py fireeye_hx --type=all
ex2)
	python commands.py helix:squid
ex3)
	python commands.py helix:paloalto
ex4)
	python commands.py crowdstrike
'''

parser = argparse.ArgumentParser(description=TOP_HELP)

def _set_argement():
	parser.add_argument('product',
		choices=['helix:squid', 'helix:paloalto', 'cbdefense', 'fireeye_hx', 'crowdstrike'],
		help='select ioc check product.') 
	parser.add_argument('-t', '--ioc_type',
			choices=['all', 'hash', 'ipaddr', 'url'],
			default='all',
			help='ioc type. all is all of supported ioc type.')
	parser.add_argument('-c', '--customers',
			default=None,
			help='target customer_names. if want to do multi customers, please separate by comma(,).')
	parser.add_argument('--splunk',
			choices=_SPLUNK.keys(),
			default="localhost",
			help="log stored splunk. if you not set this, search at localhost.")

def _get_ioc_by_yesterday(ioc_type, ioc_num=5000):
	logger.debug("check ioc by {}".format(ioc_type))
	_ioc = searcher.IocChecker()
	return _ioc.get_iocs(ioc_num=ioc_num)

def _search_by_ioc(iocs, cfg, _splunk_key, customers, product):
	splunk_server = _SPLUNK[_splunk_key]
	if product == "fireeye_hx":
		_check_by_fireeye_hx(customers, iocs, splunk_server, cfg)
	elif product == "cbdefense":
		_check_by_cbdefense(customers, iocs, splunk_server, cfg)
	elif product == "crowdstrike":
		_check_by_crowdstrike(customers, iocs, splunk_server, cfg)
	else:
		assert False, "unsupported:{}".format(product)

def _grep_valid_customers(customers, cls):
	all_customers = cls.get_api_customers()
	customers = [ each for each in  customers.split(",")
			if each in all_customers ] if customers else all_customers
	return customers
	
def _check_by_cbdefense(customers, iocs, splunk_server, cfg):
	customers = _grep_valid_customers(customers, cbdefense)
	for customer_name in customers:
		try:
			checker = cbdefense.CbdefenseIocSearcher(customer_name, splunk_server, cfg)
			results = checker.check_ioc(iocs)
		except ValueError as e:
			logger.error("error occurred by {}".format(customer_name))
			logger.exception(e)

def _check_by_crowdstrike(customers, iocs, splunk_server, cfg):
	customers = _grep_valid_customers(customers, cbdefense)
	for customer_name in customers:
		try:
			checker = crowdstrike.CrowdstrikeIocSearcher(customer_name, splunk_server, cfg)
			results = checker.check_ioc(iocs)
		except ValueError as e:
			logger.error("error occurred by {}".format(customer_name))
			logger.exception(e)

def _check_by_fireeye_hx(customers, iocs, splunk_server, cfg):
	customers = _grep_valid_customers(customers, fireeye_hx)
	for customer_name in customers:
		checker = fireeye_hx.FeHxIocSearcher(customer_name, splunk_server, cfg)
		results = checker.check_ioc(iocs)

def main():
	logger.debug("parse arguments")
	with open(_GEN_CONF) as f:
		cfg = json.load(f)
	_set_argement()
	args = parser.parse_args()
	iocs = _get_ioc_by_yesterday(args.ioc_type)
	result = _search_by_ioc(iocs, cfg, args.splunk, args.customers, args.product)

if __name__ == '__main__':
	os.chdir(MODULE_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("check_analyst_result")
	logger_util.change_permission_log_file(LOG_DIR)
	searcher.logger = logger
	try:
		main()
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)

