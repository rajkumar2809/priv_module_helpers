# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import logging

from ioc_parser import cyfirma_searcher, dhsoc_searcher

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

_IOC_SPLUNK = "splunk-license01.dhsoc.jp"

logger = logging.getLogger()

_CUSTOM     = 0
_TODAY      = 11
_YESTERDAY  = 10
_THIS_MONTH = 20
_LAST_MONTH = 21

_IOC_SRC = {
	dhsoc_searcher.Checker.source : dhsoc_searcher.Checker,
	cyfirma_searcher.Checker.source : cyfirma_searcher.Checker
}

_IOC_TYPE = [ "url", "ip", "domain", "sha256", "sha1", "md5" ]

def cache_all_iocs(hashlist=None, addrlist=None, hostlist=None,
		limit=100):
	assert hashlist or addrlist or hostlist, "need any values"
	checker = IocChecker()
	results = { "hash" : [], "addr" : [], "host" : [] }
	if hashlist:
		logger.info("search hash num:{}".format(len(hashlist)))
		for i in range(0, (len(hashlist)/limit)+1):
			each = hashlist[i*limit:limit*(i+1)]
			results["hash"].extend( checker.check_hashes(each) )
	if addrlist:
		logger.info("search addr num:{}".format(len(addrlist)))
		for i in range(0, (len(addrlist)/limit)+1):
			each = addrlist[i*limit:limit*(i+1)]
			results["addr"].extend( checker.check_ipv4(each) )
	if hostlist:
		logger.info("search domain num:{}".format(len(hostlist)))
		for i in range(0, (len(hostlist)/limit)+1):
			each = hostlist[i*limit:limit*(i+1)]
			results["host"].extend( checker.check_domains(each) )
	return results

def set_local_cache(data):
	IocChecker.set_local_cache(data)

class IocChecker(object):
	_LOCAL_CACHEs = { "hash" : {}, "addr" : {}, "host" : {} }

	@classmethod
	def set_local_cache(cls, data):
		cls._LOCAL_CACHEs = data

	def __init__(self, ioc_src="all"):
		if ioc_src == "all":
			self.source = [ each() for each in _IOC_SRC.values() ]
		else:
			self.source = [ _IOC_SRC[ioc_src]() ]

	def get_iocs(self, date_range=_YESTERDAY, ioc_num=500):
		results = {}
		for each in _IOC_TYPE:
			results[each] = []
		for each in self.source:
			each_result = each.get_iocs(date_range=date_range)
			for each_type in _IOC_TYPE:
				results[each_type].extend(each_result[each_type])
		for k, v in results.items():
			logger.info("ioc Type:{} Num:{}".format(k, len(v)))
		return results

	def check_hashes(self, values):
		logger.info("check hashes Num:{}".format(len(values)))
		values, results = self._grep_by_local_cache(values, "hash")
		for each in self.source:
			results.extend(each.check_hashes(values))
		if len(results) is not 0:
			logger.info("detected hashes Num:{}".format(len(results)))
		return results

	def check_ipv4(self, values):
		logger.info("check IPv4 Num:{}".format(len(values)))
		values, results = self._grep_by_local_cache(values, "addr")
		for each in self.source:
			results.extend(each.check_ipv4(values))
		if len(results) is not 0:
			logger.info("detected ipaddr Num:{}".format(len(results)))
		return results

	def check_domains(self, values):
		logger.info("check domains Num:{}".format(len(values)))
		values, results = self._grep_by_local_cache(values, "host")
		for each in self.source:
			results.extend(each.check_domains(values))
		if len(results) is not 0:
			logger.info("detected domain Num:{}".format(len(results)))
		return results

	def _grep_by_local_cache(self, values, _type):
		results = []
		if _type in self._LOCAL_CACHEs:
			tmp = []
			data = self._LOCAL_CACHEs[_type]
			for each in values:
				if isinstance(each, basestring):
					if each in data:
						res = data[each]
						if res["detected"]:
							results.append(res["rawdata"])
					else:
						tmp.append(each)
			values = tmp
		return values, results

def test_search_yesterday():
	checker = IocChecker()
	result = checker.get_iocs(date_range=_TODAY)
	print len(result)

def test_search_domain():
	checker = IocChecker()
	values = [
		"hmamail.com", 
		"droptop6.com",
		"t.amynx.com"
	]
	results = checker.check_domains(values)
	print json.dumps(results, indent=4)

def test_search_ipv4():
	checker = IocChecker()
	values = [
		"1.1.1.1",
		"52.218.106.116",
		"52.218.108.44",
		"176.121.14.175"
	]
	results = checker.check_ipv4(values)
	print json.dumps(results, indent=4)

def test_search_hash():
	checker = IocChecker()
	values = [
		"0000000000000000000000000000000000000000000000000000000000000000",
		"90b2d35cd5e08370ed20db81197dd9da1a4dbb421f71293fd5733ea49eb7b3e1",
		"a8c0c5edac7bb8fe380407bb2f9a2daf217b70850af0ca91d0adcb609afad57b",
		"222a65557214bb435a3cacc0956fbe233533b935fbb51d6bdad2b314859cda4a"
	]
	results = checker.check_hashes(values)
	print json.dumps(results, indent=4)

def __main__():
	logging.basicConfig(level=logging.DEBUG)
	#test_search_yesterday()
	#test_search_ipv4()
	#test_search_hash()
	test_search_domain()

if __name__ == '__main__':
	__main__()

