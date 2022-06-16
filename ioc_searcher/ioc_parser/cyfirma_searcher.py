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

	def get_iocs(self, date_range=_YESTERDAY, ioc_num=5000):
		query = self._get_query4ioc_all(date_range)
		rawinfo = [ json.loads(each["_raw"])
					for each in self.splunk.raw_search(query, max_count=ioc_num) ]
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
		res = self._search_splunk_wCyfirma(query, values)
		results.extend(res)
		if len(results) is 0:
			logger.debug("unknown by cyfirma IOC.")
		else:
			logger.debug("detected by cyfirma.")
		return results

	def check_domains(self, domains):
		if isinstance(domains, basestring):
			domains = [ domains ]
		values, results = self._split_by_known_result(domains)
		if len(values) is 0:
			return results
		query = self._get_query4domain(values)
		res = self._search_splunk_wCyfirma(query, values)
		results.extend(res)
		if len(results) is 0:
			logger.debug("unknown by cyfirma IOC.")
		else:
			logger.debug("detected by cyfirma.")
		return results

	def check_hashes(self, hashes):
		logger.debug("*** cache Num:{} ****".format(len(self._SEARCH_VALUEs)))
		if isinstance(hashes, basestring):
			hashes = [ hashes ]
		values, results = self._split_by_known_result(hashes)
		if len(values) is 0:
			return results
		query = self._get_query4hash(values)
		res = self._search_splunk_wCyfirma(query, values)
		results.extend(res)
		if len(results) is 0:
			logger.debug("unknown by cyfirma IOC.")
		else:
			logger.debug("detected by cyfirma.")
		return results

# private
	def _extend_nest_list(self, values):
		tmp = []
		for v in values:
			if isinstance(v, list):
				for each in v:
					if each and len(each) is not 0:
						tmp.append(each)
			elif v and len(v) is not 0:
				tmp.append(v)
		return tmp

	def _split_by_known_result(self, all_values):
		all_values = self._extend_nest_list(all_values)
		values = []
		results = []
		if all_values and len(all_values)>0:
			for each in all_values:
				if each in self._SEARCH_VALUEs:
					logger.debug("Known -> {} : {} : {}".format(
						each, each in self._SEARCH_VALUEs,
						self._SEARCH_VALUEs.get(each)))
					tmp = self._SEARCH_VALUEs[each]
					if tmp:
						results.append(tmp)
				else:
					logger.debug("UnKnown -> {}".format(each))
					values.append(each)
		return values, results

	def _parse_ioc_info(self, rawinfo):
		def parse_hashes(hashes):
			res = {}
			for each in hashes:
				_hash = each["simpleHashValue"]["value"]
				_type = each["type"]["value"].lower()
				res[_type] = _hash
			return res
		result = { "url" : [], "ip"   : [], "domain" : [],
				"sha256" : [], "sha1" : [], "md5"    : [] }
		for each in rawinfo:
			try:
				_property = each["observable"]["object"]["properties"]
				_title = each["title"]
				if _title == "Malicious URL Indicator":
					value = _property["value"]["value"]
					if not value in result["url"]:
						result["url"].append(value)
				elif _title == "Malicious FQDN Indicator":
					value = _property["value"]["value"]
					if not value in result["domain"]:
						result["domain"].append(value)
				elif _title == "Malicious IPv4 Indicator":
					value = _property["addressValue"]["value"]
					if not value in result["ip"]:
						result["ip"].append(value)
				elif _title == "Malicious File Indicator":
					value = parse_hashes(_property["hashes"]["hashes"])
					for key in ["md5", "sha1", "sha256"]:
						if key in value:
							if not value in result[key]:
								result[key].append(value[key])
			except KeyError as e:
				logger.warning("key error")
			except ValueError as e:
				logger.warning("value error")
		return result

	def _get_query4ioc_all(self, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		q += ' ("Malicious URL Indicator" OR "Malicious FQDN Indicator" OR "Malicious IPv4 Indicator" OR "Malicious File Indicator") '
		q += '| table _raw'
		return q

	def _get_query4url(self, values=None, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		q += ' "Malicious URL Indicator" '
		if values:
			q += ' AND ( {} ) '.format(" OR ".join(values) )
		q += '| rename '
		q += ' observable.object.properties.value.value as searchvalue '
		q += '| eval ioc_type="url" '
		q += '| eval detail="detected by cyfirma" '
		q += '| eval severity="medium" '
		q += '| eval ioc_source="cyfirma" '
		q += '| table _time,id,searchvalue,ioc_source,ioc_type,severity,detail'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_query4domain(self, values=None, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		q += ' "Malicious FQDN Indicator" '
		if values:
			q += ' AND ( {} ) '.format(" OR ".join(values) )
		q += '| rename '
		q += ' observable.object.properties.value.value as searchvalue '
		q += '| eval ioc_type="domain" '
		q += '| eval detail="detected by cyfirma" '
		q += '| eval severity="medium" '
		q += '| eval ioc_source="cyfirma" '
		q += '| table _time,id,searchvalue,ioc_source,ioc_type,severity,detail'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_query4ipv4(self, values=None, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		q += ' "Malicious IPv4 Indicator" '
		if values:
			q += ' AND ( {} ) '.format(" OR ".join(values) )
		q += '| rename '
		q += ' observable.object.properties.addressValue.value as searchvalue'
		q += '| eval ioc_type="ipv4" '
		q += '| eval detail="detected by cyfirma" '
		q += '| eval severity="medium" '
		q += '| eval ioc_source="cyfirma" '
		q += '| table _time,id,searchvalue,ioc_source,ioc_type,severity,detail'
		q += '| dedup searchvalue sortby _time desc'
		return q

	def _get_query4hash(self, values=None, date_range=None):
		earliest, latest = self._get_date_range(date_range)
		q  = 'search index="{}" source="{}" earliest={} latest={} '.format(
				self.index, self.source, earliest, latest )
		q += ' "Malicious File Indicator" '
		if values:
			q += ' AND ( {} ) '.format(" OR ".join(values) )
		q += '| rename observable.object.properties.fileName.value as file_name '
		q += ' observable.object.properties.hashes.hashes{}.simpleHashValue.value as searchvalue '
		q += '| eval ioc_type="sha256" '
		q += '| eval detail="detected by cyfirma" '
		q += '| eval severity="medium" '
		q += '| eval ioc_source="cyfirma" '
		q += '| table _time,id,searchvalue,ioc_source,ioc_type,severity,detail'
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

	def _search_splunk_wCyfirma(self, query, values):
		def extend_nest_list(values):
			tmp = []
			for v in values:
				if isinstance(v, list):
					for each in v:
						if each and len(each) is not 0:
							tmp.append(each)
				elif v and len(v) is not 0:
					tmp.append(v)
			return tmp

		values = extend_nest_list(values)
		results = self.splunk.raw_search(query)
		for each in results:
			for v in values:
				if v in each["searchvalue"]:
					each["searchvalue"] = v
					logger.debug("{} is detected.".format(v))
					self._SEARCH_VALUEs[v] = each
				#elif isinstance(v, list): #TODO maybe delete(20/06/24)
				#	logger.debug("search value type is list.")
				#	for each_v in v:
				#		if each_v in each["searchvalue"]:
				#			logger.debug("{} is detected.".format(each_v))
				#			self._SEARCH_VALUEs[each_v] = each
		for v in values:
			if not v in self._SEARCH_VALUEs:
				logger.debug("{} is undetected.".format(v))
				self._SEARCH_VALUEs[v] = None
		return results

def test_search_yesterday():
	api = Checker()
	result = api.get_iocs()
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
		"222a65557214bb435a3cacc0956fbe233533b935fbb51d6bdad2b314859cda4a" )
	results = cyfirma.check_hashes(values)
	print len(results)
	print cyfirma._SEARCH_VALUEs.keys()

def test_search_ipv4():
	cyfirma = Checker()
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
	cyfirma = Checker()
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
	#test_search_yesterday()
	#test_search_ipv4()
	test_search_hash()
	#test_search_domain()

if __name__ == '__main__':
	__main__()

