# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import logging
from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

_IOC_SPLUNK = "splunk-license01.dhsoc.jp"

logger = logging.getLogger()

_CUSTOM     = 0
_TODAY      = 11
_YESTERDAY  = 10
_THIS_MONTH = 20
_LAST_MONTH = 21

_IOC_TYPE = [ "url", "ip", "domain", "sha256", "sha1", "md5" ]

class Checker(object):
	index = "dhsoc_ioc"
	source = "dhsoc*"
	splunk_app = "dhsoc_ioc"
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
			cls.splunk.init_splunk_by_cfg_file(cfg_name, app=cls.splunk_app)
		cls._IS_INIT = True
	
	def __init__(self):
		if not self._IS_INIT:
			self.init_splunk()

	def get_iocs(self, date_range=_YESTERDAY, ioc_num=500):
		query = self._get_query4ioc_all(date_range)
		rawinfo = [ dict(each) for each in self.splunk.raw_search(
			query, max_count=ioc_num) ]
		logger.debug("ioc num is {}".format(len(rawinfo)))
		iocs = self._parse_ioc_info(rawinfo)
		for k, v in iocs.items():
			logger.debug("ioc Type:{} Num:{}".format(k, len(v)))
		return iocs

	def check_ipv4(self, addresses):
		if isinstance(addresses, basestring):
			addresses = [ addresses ]
		values, results = self._split_by_known_result(addresses)
		if len(values) is 0:
			return results
		query = self._get_query4ipv4(values)
		res = self._search_splunk(query, values)
		results.extend(res)
		if len(results) is 0:
			logger.debug("unknown by {} IOC.".format(self.source))
		else:
			logger.debug("detected by {}.".format(self.source))
		return results

	def check_domains(self, domains):
		if isinstance(domains, basestring):
			domains = [ domains ]
		values, results = self._split_by_known_result(domains)
		if len(values) is 0:
			return results
		query = self._get_query4domain(values)
		res = self._search_splunk(query, values)
		results.extend(res)
		if len(results) is 0:
			logger.debug("unknown by {} IOC.".format(self.source))
		else:
			logger.debug("detected by {}.".format(self.source))
		return results

	def check_hashes(self, hashes):
		if isinstance(hashes, basestring):
			hashes = [ hashes ]
		values, results = self._split_by_known_result(hashes)
		if len(values) is 0:
			return results
		query = self._get_query4hash(values)
		res = self._search_splunk(query, values)
		results.extend(res)
		if len(results) is 0:
			logger.debug("unknown by {} IOC.".format(self.source))
		else:
			logger.debug("detected by {}.".format(self.source))
		return results

# private
	def _split_by_known_result(self, all_values):
		values = []
		results = []
		if all_values and len(all_values)>0:
			for each in all_values:
				if each in self._SEARCH_VALUEs:
					tmp = self._SEARCH_VALUEs[each]
					if tmp:
						results.append(tmp)
				else:
					values.append(each)
		return values, results

	def _parse_ioc_info(self, rawinfo):
		result = { "url" : [], "ip"   : [], "domain" : [],
				"sha256" : [], "sha1" : [], "md5"    : [] }
		for each in rawinfo:
			try:
				ioc_type = each["ioc_type"]
				if ioc_type in result:
					result[ioc_type].append(each["searchvalue"])
			except KeyError as e:
				logger.warning("key error")
				logger.exception(e)
			except ValueError as e:
				logger.warning("value error")
				logger.exception(e)
		return result

	def _get_query4ioc_all(self, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		q += '| rename value as searchvalue '
		q += '| table searchvalue,ioc_type,ioc_source,severity,detail'
		return q

	def _get_query4url(self, values=None, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		if values:
			q += ' {} '.format(" OR ".join(values) )
		q += '| where ioc_type="url" '
		q += '| rename value as searchvalue '
		q += '| table searchvalue,ioc_type,ioc_source,severity,detail'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_query4domain(self, values=None, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		if values:
			q += ' {} '.format(" OR ".join(values) )
		q += '| where ioc_type="domain" '
		q += '| rename value as searchvalue '
		q += '| table searchvalue,ioc_type,ioc_source,severity,detail'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_query4ipv4(self, values=None, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		if values:
			q += ' ({}) '.format(" OR ".join(values) )
		q += '| where ioc_type="ip" '
		q += '| rename value as searchvalue '
		q += '| table searchvalue,ioc_type,ioc_source,severity,detail'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_query4hash(self, values=None, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		if values:
			q += ' ({}) '.format(" OR ".join(values) )
		q += '| where ioc_type="md5" OR ioc_type="sha1" OR ioc_type="sha256" '
		q += '| rename value as searchvalue '
		q += '| table searchvalue,ioc_type,ioc_source,severity,detail'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_date_range(self, date_range=None):
		if date_range is None:
			return "-1y@y", "now"
		elif date_range is _YESTERDAY:
			return "-1d@d", "@d"
		elif date_range is _TODAY:
			return "@d", "now"
		elif date_range is _THIS_MONTH:
			return "@mon", "now"
		elif date_range is _LAST_MONTH:
			return "-1mon@mon", "@mon"
		else:
			assert False, "unsupported current."

	def _search_splunk(self, query, values):
		results = self.splunk.raw_search(query)
		for each in results:
			for v in values:
				if isinstance(each["searchvalue"], basestring):
					each["searchvalue"] = [ each["searchvalue"] ]
				if v in each["searchvalue"]:
					logger.debug( "match")
					each["searchvalue"] = v
					logger.debug("{} is detected.".format(v))
					self._SEARCH_VALUEs[v] = each
				elif isinstance(v, list):
					logger.debug("search value type is list.")
					for each_v in v:
						if each_v in values:
							logger.debug("{} is detected.".format(each_v))
							self._SEARCH_VALUEs[each_v] = each
		for v in values:
			if not v in self._SEARCH_VALUEs:
				logger.debug("{} is undetected.".format(v))
				self._SEARCH_VALUEs[v] = None
		return results

def test_search_yesterday():
	api = Checker()
	result = api.get_iocs(_TODAY)
	print len(result)

def test_search_hash():
	cyfirma = Checker()
	values = [ "0000000000000000000000000000000000000000000000000000000000000000" ]
	results = cyfirma.check_hashes(values)
	print len(results)
	values.append(
		"90b2d35cd5e08370ed20db81197dd9da1a4dbb421f71293fd5733ea49eb7b3e1" )
	results = cyfirma.check_hashes(values)
	print len(results)
	values.append(
		"a8c0c5edac7bb8fe380407bb2f9a2daf217b70850af0ca91d0adcb609afad57b" )
	results = cyfirma.check_hashes(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()

def test_search_ipv4():
	cyfirma = Checker()
	values = [ "1.1.1.1" ]
	print values
	results = cyfirma.check_ipv4(values)
	print results
	values.append( "176.121.14.175" )
	results = cyfirma.check_ipv4(values)
	print len(results)
	results = cyfirma.check_ipv4(values)
	print len(results)
	values.append( "194.68.27.38" )
	results = cyfirma.check_ipv4(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()

def test_search_domain():
	cyfirma = Checker()
	values = [ "attacker.tech-oshiba.com" ]
	print values
	results = cyfirma.check_domains(values)
	print len(results)
	values.append( "jp-microsoft-store.com" )
	values.append( "t.amynx.com" )
	print values
	results = cyfirma.check_domains(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()
	results = cyfirma.check_domains(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()

def __main__():
	logging.basicConfig(level=logging.DEBUG)
	#test_search_yesterday()
	test_search_ipv4()
	#test_search_hash()
	#test_search_domain()

if __name__ == '__main__':
	__main__()

