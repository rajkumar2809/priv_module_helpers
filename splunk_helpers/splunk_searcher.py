# -*- coding: utf-8 -*-

import os, sys
import json, copy
from time import sleep, mktime
from monkey_tools.utils import logger_util
from monkey_tools.utils.splunk_search_util import SplunkSearcher

dirpath = os.path.dirname( os.path.abspath(__file__) )
_CONF_PATH = dirpath+"/config"
_CONF = "splunk-license.json"

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

def get_logger(log_name="mysplunk_searcher"):
	return MyLogger.get_logger(log_name)

class MySearcher(object):
	splunk_searcher = None

	@classmethod
	def make_query(cls, queries, index, earliest=None, latest=None, transform=None):
		"""
		make query string for splunk search.
		and this query search after savedsearch.
		"""
		query_top = u'| search index="{}"'.format(index)
		if earliest: 
			query_top += u'earliest="{}"'.format(earliest)
		if latest: 
			query_top += u'latest="{}"'.format(latest)
		query = []
		query.append(query_top)
		for key,value in queries.items():
			query.append(u' AND ({0} = "{1}" OR {0} = "all") '.format(key, value))
		if transform:
			query.append(transform)
		return "\n".join(query)

	@classmethod
	def transform4hash(cls):
		words  = '| table _time,hash,risk,fprate,category,name,customer_name,enabled,description'
		words += '| dedup hash sortby -_time'
		return words

	@classmethod
	def is_init(cls):
		return cls.splunk_searcher is not None

	@classmethod
	def init_splunk(cls, host, port, protocol, app, username, password):
		cls.splunk_searcher = SplunkSearcher(
			host, port, app, username, password)

	@classmethod
	def init_splunk_by_cfg_file(cls, cfg_name=None, cfg_dir=None, **spconf):
		if cfg_dir is None:
			cfg_dir = _CONF_PATH
		if cfg_name is None:
			cfg_name = _CONF
		if not cfg_name.endswith(".json"):
			cfg_name = cfg_name+".json"
		with open("{}/{}".format(cfg_dir, cfg_name)) as f:
			cfg = json.load(f)
		cfg.update(spconf)
		cls.splunk_searcher = SplunkSearcher(
			cfg["host"], cfg["port"], cfg["app"], cfg["username"], cfg["password"])

	@classmethod
	def search(cls, queries, index, earliest=None, latest=None, transform=None, exec_mode="blocking", max_count=100):
		query = cls.make_query(queries, index, earliest, latest, transform)
		return cls.splunk_searcher.search(query, exec_mode=exec_mode, max_count=max_count)

	@classmethod
	def raw_search(cls, query, exec_mode="blocking", max_count=100):
		return cls.splunk_searcher.search(query, exec_mode=exec_mode, max_count=max_count)

def _transform4iocHash():
	words  = '| table _time,hash,risk,fprate,category,name,customer_name,enabled,description'
	words += '| dedup hash sortby -_time'
	return words

def __test__():
	logger = get_logger()
	logger.info( "start" )
	logger.info( "parse and set configuration" )
	MySearcher.init_splunk_by_cfg_file()
	logger.info( "search splunk" )
	index = "dhsoc_hash_info"
	queries = {}
	queries["hash"] = "8c78f9741f9a8a3e54aaaf3d3f3f99bcd7f5d9b66428f20015a57bc38b574bbc"
	result = MySearcher.search(queries, index, transform=_transform4iocHash())
	print [ dict(each) for each in result ]
	logger.info("results Num:{}".format(len(result)))
	queries["customer_name"] = "YSN1"
	result = MySearcher.search(queries, index, transform=_transform4iocHash())
	print [ dict(each) for each in result ]
	logger.info("results Num:{}".format(len(result)))
	logger.info( "end" )

def __test__cs():
	logger = get_logger()
	logger.info( "start 2" )
	logger.info( "parse and set configuration" )
	MySearcher.init_splunk_by_cfg_file('splunk-production00')
	logger.info( "search splunk" )
	#queries = "| search index=mdr_report_cs ldt:75a6e0272f7840e36cd70244badfbd75:81604387549"
	queries = '| `cs_reportdata_base(*,ldt:75a6e0272f7840e36cd70244badfbd75:81604387549,*,now,-30d@d)`'
	result = MySearcher.raw_search(queries)
	print len(result)

if __name__ == '__main__':
	try:
		MyLogger._IS_TEST = True
		__test__cs()
	except StandardError as e:
		logger = get_logger()
		logger.error(e.message)
		logger.exception(e)

