# -*- coding: utf-8 -*-

# TODO:will be delete!!

import os, sys
import json, re, glob
import logging
from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

_IOC_SPLUNK = "splunk-license01.dhsoc.jp"

logger = logging.getLogger()

def cache_all_iocs(hashlist=None, addrlist=None, hostlist=None,
		limit=5000):
	assert hashlist or addrlist or hostlist, "need any values"
	if not CyfirmaChecker._IS_INIT:
		CyfirmaChecker.init_splunk()
	checker = CyfirmaChecker()
	if hashlist:
		logger.info("search hash num:{}".format(len(hashlist)))
		for i in range(0, (len(hashlist)/limit)+1):
			each = hashlist[i*limit:limit*(i+1)]
			checker.check_hashes(each)
	if addrlist:
		logger.info("search addr num:{}".format(len(addrlist)))
		for i in range(0, (len(addrlist)/limit)+1):
			each = addrlist[i*limit:limit*(i+1)]
			checker.check_ipv4(each)
	if hostlist:
		logger.info("search domain num:{}".format(len(hostlist)))
		for i in range(0, (len(hostlist)/limit)+1):
			each = hostlist[i*limit:limit*(i+1)]
			checker.check_domains(each)

class CyfirmaChecker(object):
	index = "cyfirma_ioc"
	source = "cyfirma"
	_IS_INIT = False
	_SEARCH_VALUEs = {}

	@classmethod
	def init_splunk(cls):
		cls.splunk = _splunk.MySearcher
		if not cls.splunk.is_init():
			if "." in _IOC_SPLUNK:
				cfg_name = _IOC_SPLUNK.split(".")[0]
			else:
				cfg_name = _IOC_SPLUNK
			cls.splunk.init_splunk_by_cfg_file(cfg_name, app="dhsoc_ioc")
		cls._IS_INIT = True
	
	def __init__(self):
		if not self._IS_INIT:
			self.init_splunk()

	def check_ipv4(self, addresses):
		if isinstance(addresses, basestring):
			addresses = [ addresses ]
		values = []
		results = []
		for each in addresses:
			if addresses and len(addresses)>0:
				if each in self._SEARCH_VALUEs:
					tmp = self._SEARCH_VALUEs[each]
					if tmp:
						results.append(tmp)
				else:
					values.append(each)
		if len(values) is 0:
			return results
		query = self._get_query4ipv4(values)
		res = self._search_splunk_wCyfirma(query, values)
		results.extend(res)
		if len(res) is 0:
			logger.debug("unknown by cyfirma IOC.")
		else:
			logger.debug("detected by cyfirma.")
		return res

	def check_domains(self, domains):
		if isinstance(domains, basestring):
			domains = [ domains ]
		values = []
		results = []
		for each in domains:
			if each and len(each)>0:
				if each in self._SEARCH_VALUEs:
					tmp = self._SEARCH_VALUEs[each]
					if tmp:
						results.append(tmp)
				else:
					values.append(each)
		if len(values) is 0:
			return results
		query = self._get_query4domain(values)
		res = self._search_splunk_wCyfirma(query, values)
		results.extend(res)
		if len(res) is 0:
			logger.debug("unknown by cyfirma IOC.")
		else:
			logger.debug("detected by cyfirma.")
		return res

	def check_hashes(self, hashes):
		if isinstance(hashes, basestring):
			hashes = [ hashes ]
		values = []
		results = []
		for each in hashes:
			if each in self._SEARCH_VALUEs:
				tmp = self._SEARCH_VALUEs[each]
				if tmp:
					results.append(tmp)
			else:
				values.append(each)
		if len(values) is 0:
			return results
		query = self._get_query4hash(values)
		res = self._search_splunk_wCyfirma(query, values)
		results.extend(res)
		if len(res) is 0:
			logger.debug("unknown by cyfirma IOC.")
		else:
			logger.debug("detected by cyfirma.")
		return res

# private

	def _get_query4domain(self, names):
		names = [ '"{}"'.format(each) for each in names ]
		q  = 'search index="{}" source="{}" earliest=-1y '.format(
				self.index, self.source )
		q += ' "Malicious FQDN Indicator" {}'.format(
				" OR ".join(names) )
		q += '| rename '
		q += 'observable.object.properties.value.value as searchvalue '
		q += '| table _time,id,searchvalue'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_query4ipv4(self, addresses):
		addresses = [ '"{}"'.format(each) for each in addresses ]
		q  = 'search index="{}" source="{}" earliest=-1y '.format(
				self.index, self.source )
		q += ' "Malicious IPv4 Indicator" {}'.format(
				" OR ".join(addresses) )
		q += '| rename '
		q += 'observable.object.properties.addressValue.value as searchvalue'
		q += '| table _time,id,searchvalue'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_query4hash(self, hashes):
		q  = 'search index="{}" source="{}" earliest=-1y '.format(
				self.index, self.source )
		q += ' "Malicious File Indicator" {}'.format(
				" OR ".join(hashes) )
		q += '| rename observable.object.properties.fileName.value as file_name '
		q += 'observable.object.properties.hashes.hashes{}.simpleHashValue.value as searchvalue '
		q += '| table _time,id,file_name,searchvalue'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _search_splunk_wCyfirma(self, query, values):
		logger.info("search cyfirma and current num:{}".format(
			len(self._SEARCH_VALUEs)))
		results = self.splunk.raw_search(query)
		matched = {}
		for each in results:
			for v in values:
				if v in each["searchvalue"]:
					self._SEARCH_VALUEs[v] = each
		for v in values:
			if not v in self._SEARCH_VALUEs:
				self._SEARCH_VALUEs[v] = None
		return results

def test_search_hash():
	cyfirma = CyfirmaChecker()
	values = [ "0000000000000000000000000000000000000000000000000000000000000000" ]
	results = cyfirma.check_hashes(values)
	print len(results)
	values.append(
		"90b2d35cd5e08370ed20db81197dd9da1a4dbb421f71293fd5733ea49eb7b3e1" )
	results = cyfirma.check_hashes(values)
	print len(results)
	values.append(
		"222a65557214bb435a3cacc0956fbe233533b935fbb51d6bdad2b314859cda4a" )
	results = cyfirma.check_hashes(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()

def test_search_ipv4():
	cyfirma = CyfirmaChecker()
	values = [ "1.1.1.1" ]
	print values
	results = cyfirma.check_ipv4(values)
	print results
	values.append( "52.218.106.116" )
	results = cyfirma.check_ipv4(values)
	print len(results)
	results = cyfirma.check_ipv4(values)
	print len(results)
	values.append( "52.218.108.44" )
	results = cyfirma.check_ipv4(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()

def test_search_domain():
	cyfirma = CyfirmaChecker()
	values = [ "attacker.tech-oshiba.com" ]
	print values
	results = cyfirma.check_domains(values)
	print len(results)
	values.append( "hmamail.com" )
	values.append( "droptop6.com" )
	print values
	results = cyfirma.check_domains(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()
	results = cyfirma.check_domains(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()

def __main__():
	logging.basicConfig(level=logging.DEBUG)
	test_search_domain()
	test_search_ipv4()
	test_search_hash()

if __name__ == '__main__':
	__main__()

