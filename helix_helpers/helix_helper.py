# -*- encoding:utf-8
# TODO:need to make testcode
# TODO:need to be refactor apikey management

import os, sys
import json
import logging

from monkey_tools.utils import rest_util as rest
from monkey_tools.utils import time_util as time
from connectors.helix_api import helix_api as api
from query_builders import squid, eset

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
CFG_FILE = CONF_DIR+"/config.json"
with open(CFG_FILE) as f:
	CONFIG = json.load(f)

customer_name = None
_API = {
	"siem" : "apikey",
	"rest" : "rest"
}

SEARCHERs = {
	"squid" : squid.Builder,
	"eset"  : eset.Builder
}

logger = logging.getLogger("helix_helper")

def get_alert_from_sec(from_sec=300, target=None):
	if target is None:
		target = customer_name
	if target and target.lower() == "all":
		logger.info("get helix alerts with customer:{}".format(str(target)))
		result = []
		for each in _get_all_customers():
			try:
				_api=api.HelixApi(_get_key(each))
				each_res = _api.get_alerts(_get_query_from_sec(from_sec))
				result.extend(each_res["alerts"])
			except Exception as e:
				logger.warning("fail to access helix for {}".format(each))
				logger.exception(e)
		return result
	else:
		_api=api.HelixApi(_get_key(target))
		res = _api.get_alerts(_get_query_from_sec(from_sec))
		return res["alerts"]

def search(customer, query):
	_id = _get_customer_id(customer)
	key = _get_key(customer, _API["rest"])
	_api=api.HelixApi(key, customer_id=_id)
	return _api.search({"query" : query})

# private

def _get_query_from_sec(from_sec=300):
	_date = time.get_time_sec_before(from_sec, date_type=time.UNIX, utc=True)
	_date = str(_date)
	query = {
		"createDate" : { "$gt" : _date }
	}
	return json.dumps(query)

def _get_all_customers():
	return CONFIG.keys()

def _get_key(_customer, api_type=_API["siem"]):
	assert _customer and _customer in CONFIG, "dont set customer_name yet"
	key = CONFIG[_customer][api_type]
	return key.strip()

def _get_customer_id(_customer):
	assert _customer and _customer in CONFIG, "dont set customer_name yet"
	key = CONFIG[_customer]["customer_id"]
	return key.strip()

def __test_eset(customer):
	_id = _get_customer_id(customer)
	key = _get_key(customer, _API["siem"])
	_api=api.HelixApi(key, customer_id=_id)
	qbuilder = eset.Builder()
	qbuilder.set_time_around("2020-03-13 00:00:00", diff=86400)
	query = qbuilder.to_query()
	print query
	res = _api.search({"query" : query})
	print json.dumps(res, indent=4)
	#with open("eset.json", "w") as wf:
	#	json.dump(res, wf, indent=4)

def __test_squid(customer):
	_id = _get_customer_id(customer)
	key = _get_key(customer, _API["siem"])
	_api=api.HelixApi(key, customer_id=_id)
	qbuilder = squid.Builder()
	qbuilder.set_time_around("2020-03-13 00:00:00", diff=86400)
	query = qbuilder.to_query()
	print query
	res = _api.search({"query" : query})
	for each in res["results"]["hits"]["hits"]:
		info = qbuilder.parse_result(each)
		print json.dumps(info, indent=4)
	#with open("squid.json", "w") as wf:
	#	json.dump(res, wf, indent=4)

def __main__():
	customer = "TOS1"
	__test_squid(customer)

if __name__ == '__main__':
	__main__()

