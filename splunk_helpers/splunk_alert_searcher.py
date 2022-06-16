# -*- coding: utf-8 -*-

import os, sys
import json, copy
from time import sleep, mktime
from monkey_tools.utils import logger_util
from monkey_tools.utils.splunk_search_util import SplunkSearcher

dirpath = os.path.dirname( os.path.abspath(__file__) )
_CONF_PATH = dirpath+"/config"
_CONF = "splunk.json"

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

class MyAlertSearcher(object):
	splunk_searcher = None
	defaul_earliest = "-10m@m"
	defaul_latest = "now"

	@classmethod
	def make_query(cls, queries, index, earliest=None, latest=None, transform=None):
		"""
		make query string for splunk search.
		and this query search after savedsearch.
		"""
		earliest = earliest if earliest else cls.defaul_earliest
		latest   = latest   if latest   else cls.defaul_latest
		query_top = u'| search index="{}"'.format(index)
		query_top += u'earliest="{}" latest="{}"'.format(earliest, latest)
		query = []
		query.append(query_top)
		for key,value in queries.items():
			query.append(u'AND {}="{}"'.format(key, value))
		if transform:
			query.append(transform)
		return "\n".join(query)

	@classmethod
	def is_init(cls):
		return cls.splunk_searcher is not None

	@classmethod
	def init_splunk(cls, host, port, protocol, app, username, password):
		cls.splunk_searcher = SplunkSearcher(
			host, port, app, username, password)

	@classmethod
	def init_splunk_by_cfg_file(cls, cfg_name=None, cfg_dir=None):
		if cfg_dir is None:
			cfg_dir = _CONF_PATH
		if cfg_name is None:
			cfg_name = _CONF
		with open("{}/{}".format(cfg_dir, cfg_name)) as f:
			cfg = json.load(f)
		cls.splunk_searcher = SplunkSearcher(
			cfg["host"], cfg["port"], cfg["app"], cfg["username"], cfg["password"])

	@classmethod
	def search(cls, queries, index, earliest=None, latest=None, transform=None, exec_mode="blocking", max_count=100):
		query = cls.make_query(queries, index, earliest, latest, transform)
		return cls.splunk_searcher.search(query, exec_mode=exec_mode, max_count=max_count)

def __test__():
	logger = get_logger()
	logger.info( "start" )
	conf_name = "test.json"
	logger.info( "parse and set configuration" )
	MyAlertSearcher.init_splunk_by_cfg_file(cfg_name=conf_name)
	customer_name = "YSN1"
	logger.info( "search splunk" )
	index = "mdr_report_cbd"
	queries = {}
	queries["alert_summary.alert_type"] = "ransomware"
	queries["alert_src.customer_name"]  = "YSN1"
	result = MyAlertSearcher.search(queries, index, earliest="-5d@d")
	print result
	logger.info("results Num:{}".format(len(result)))
	logger.info( "end" )

if __name__ == '__main__':
	try:
		MyLogger._IS_TEST = True
		__test__()
	except StandardError as e:
		logger = get_logger()
		logger.error(e.message)
		logger.exception(e)

