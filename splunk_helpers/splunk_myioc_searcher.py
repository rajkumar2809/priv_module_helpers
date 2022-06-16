# -*- coding: utf-8 -*-

import os, sys
import json, copy
from time import sleep, mktime
from monkey_tools.utils import logger_util
from monkey_tools.utils.splunk_search_util import SplunkSearcher

class MyLogger(object):
	Loggers = {}
	_IS_TEST = False

	@classmethod
	def get_logger(cls, log_name):
		if cls.Loggers.has_key(log_name):
			return cls.Loggers[log_name]
		else:
			logger = cls._make_logger(log_name)
			cls.Loggers[log_name] = logger
			return logger

	@classmethod
	def _make_logger(cls, log_name):
		if cls._IS_TEST:
			return logger_util._get_stream_logger(log_name)
		else:
			return logger_util.get_standard_logger(log_name)

def get_logger(log_name="myioc_searcher"):
	return MyLogger.get_logger(log_name)

class MyIntelSearcher(object):
	records = {}
	splunk_searcher = None
	SET_ALL = False

	@staticmethod
	def make_query(value, product=None, user=None, rec_type=None):
		"""
		make query string for splunk search.
		and this query search after savedsearch.
		"""
		query = []
		query_top = u'| savedsearch search_valid_threat_info'
		query.append(query_top)
		if value or product or user or rec_type:
			query.append(u'| search ')
			conditions = []
			if user:
				conditions.append(u'(user=\"{}\" OR user=ALL) '.format(user))
			if product:
				conditions.append(u'(product=\"{}\" OR product=ALL) '.format(product))
			if rec_type:
				conditions.append(u'type=\"{}\" '.format(rec_type))
			if value:
				conditions.append(u'value=\"{}\" '.format(value))
			query.append(" AND ".join(conditions))
			query.append(u'| sort by score desc')
		return "\n".join(query)

	@classmethod
	def get_all_threat_ioc(cls, product=None):
		q = cls.make_query(None, product=product)
		return cls.splunk_searcher.search(q, exec_mode="blocking", max_count=0)

	@classmethod
	def set_all_threat_ioc2cache(cls, product=None):
		raw_result = cls.get_all_threat_ioc(product=product)
		result = []
		for each in raw_result:
			try:
				result.append(_parse_json_rawdata(each))
			except ValueError as e:
				logger.warning("ValueEroror with {} at json load".format(e.message))
			except KeyError as e:
				logger.warning("KeyEroror with {} at json load".format(e.message))
		cls.add_all_by_records(result)
		cls.SET_ALL = True

	@classmethod
	def search_cache(cls, value, product=None, user=None, rec_type=None):
		logger = get_logger()
		if cls.records.has_key(value):
			logger.debug("serch target value exist")
			records = []
			logger.debug(
				"Chk by: Product:{} User:{} RecType:{}".format(
					product, user, rec_type))
			for each in cls.records[value]:
				if cls.match_2nd_key(
						each, product, user, rec_type):
					logger.debug("2nd key is match!")
					records.append(each["data"])
			return records
		else:
			logger.debug("serch target value unexist")
			return []
		return records

	@classmethod
	def match_2nd_key(cls, record, product, user, rec_type):
		def match_each(target, current):
			target = target.lower() if target else "all"
			current = current.lower() if current else "all"
			logger.debug(
				"Chk With {}->{}".format(target, current))
			if target == "all" or current == "all":
				logger.debug("match by wildcard!")
				return True
			elif target == current:
				logger.debug("match by correct value!")
				return True
			else:
				return False

		logger = get_logger()
		logger.debug("check match by product")
		if not match_each(record["product"], product):
			logger.debug("product dont match")
			return False
		logger.debug("check match by user")
		if not match_each(record["user"], user):
			logger.debug("user dont match")
			return False
		logger.debug("check match by rec_type")
		if not match_each(record["type"], rec_type):
			logger.debug("rec_type dont match")
			return False
		return True

	@classmethod
	def is_init(cls):
		return cls.splunk_searcher is not None

	@classmethod
	def init_splunk(cls, host, port, protocol, app, username, password):
		cls.splunk_searcher = SplunkSearcher(
			host, port, app, username, password)

	@classmethod
	def add(cls, data, value, product=None, user=None, rec_type=None):
		def make_record(data, product, user, rec_type):
			product  = product  if product  else "all"
			user     = user     if user     else "all"
			rec_type = rec_type if rec_type else "all"
			return {"data" : data, "product"  : product,
					"user" : user, "type"     : rec_type }

		logger = get_logger()
		if not cls.records.has_key(value):
			logger.debug("make new record")
			cls.records[value] = []
		record = make_record(data, product, user, rec_type)
		cls.records[value].append(record)

	@classmethod
	def add_all_by_records(cls, records):
		for each in records:
			value    = each["value"]
			product  = each["product"]
			user     = each["user"]
			rec_type = each["type"]
			cls.add(each, value, product, user, rec_type)

	@classmethod
	def clone_records(cls):
		return copy.copy(cls.records)

	@classmethod
	def get_all(cls):
		results = []
		for each in cls.records.values():
			results.extend(each)
		return results

	@classmethod
	def get(cls, value, product=None, user=None, rec_type=None):
		return cls.search_cache(value, product, user, rec_type)

	@classmethod
	def has(cls, value, product=None, user=None, rec_type=None):
		records = cls.search_cache(value, product, user, rec_type)
		return len(records)>0

	@classmethod
	def del_records(cls, value, product=None, user=None, rec_type=None):
		if cls.records.has_key(value):
			if product or user or rec_type:
				records = cls.records[value]
				for i in reversed(range(0, len(records))):
					each = records[i]
					if cls.match_2nd_key(each, product,user,rec_type):
						del records[i]
			else:
				del cls.records[value]

	@classmethod
	def clear(cls):
		cls.records.clear()

	@classmethod
	def search(cls, value, product=None, user=None, rec_type=None, exec_mode="blocking", max_count=100, logger=None, max_retry=3):
		if logger is None:
			logger = get_logger()
		if cls.has(value, product, user, rec_type):
			logger.info("search by cache")
			return cls.get(value, product, user, rec_type)
		elif cls.SET_ALL:
			return [] #because already check cache by above
		else:
			logger.info("search by splunk")
			query = cls.make_query(value, product, user, rec_type)
			result = None
			for i in range(0, max_retry):
				try:
					result = cls.splunk_searcher.search(query, exec_mode=exec_mode, max_count=max_count)
					break
				except IOError as e:
					logger.warning("Access Error at search Splunk.")
					sleep(2)
			if result is None:
				assert False, "Cannnot Access Splunk."
			try:
				result = _parse_all_json_rawdata(result)
			except ValueError as e:
				logger.warning("ValueEroror with {} at json load".format(e.message))
			cls.add_all_by_records(result)
			return result

def search(value, product=None, user=None, rec_type=None, exec_mode="blocking", max_count=100, logger=None):
		return MyIntelSearcher.search(value, product, user, rec_type, exec_mode, max_count, logger)

def _parse_all_json_rawdata(data_list):
	result = []
	for each in data_list:
		if each.has_key("_raw"):
			result.append(_parse_json_rawdata(each))
	return result

def _parse_json_rawdata(data):
	_raw =  data["_raw"]
	return json.loads(_raw)

def __test__():
	logger = get_logger()
	logger.info( "start" )
	#onf_name = "config/splunk.json"
	conf_name = "config/splunk-license.json"
	with open(conf_name, "r") as f:
		cfg = json.load(f)
	MyIntelSearcher.init_splunk( **cfg )
	MyIntelSearcher.set_all_threat_ioc2cache()
	logger.info( "parse and set configuration" )
	user = "gdo"
	product = "cbdefense"
	rec_type = "condition"
	logger.info("search by new app name")
	apps = ["explorer.exe", "powershell.exe", "cmd.exe"]
	for each in apps:
		result = search(each, product, user, rec_type)
	logger.info("search by same app name")
	for each in apps:
		result = search(each, product, user, rec_type)
	apphash = '723ced878c818b16863c181f41e5374ba57740339cf446305f6f2b855ef7b647'
	result = search(apphash, product, user, "hash")
	logger.info("{} -> {}".format(apphash, str(result)))
	logger.info("cached IOC Num:{}".format(len(MyIntelSearcher.get_all())))
	#logger.info("Cache Keys are ::> {}".format( "; ".join(MyIntelSearcher.get_all()) ))
	logger.info( "end" )

if __name__ == '__main__':
	try:
		MyLogger._IS_TEST = True
		__test__()
	except StandardError as e:
		logger = get_logger()
		logger.error(e.message)
		logger.exception(e)

