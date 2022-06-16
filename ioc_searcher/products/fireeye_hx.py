# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import logging

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

logger = logging.getLogger()

from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk
from priv_module_helpers.splunk_helpers import splunk_post_helper as _splunk_post
from priv_module_helpers.hxapi_helpers import hx_api_helper as _hxapi

def get_api_customers():
	return _hxapi.get_customers()

import base

class FeHxIocSearcher(base.IocSearcher):
	_PRODUCT = "fireeye_hx"

	def check_ioc(self, iocs):
		logger.info("targe customer:{}".format(self.customer_name))
		self._work_for_current_search()
		if self.max_num > 0:
			search_values = self._parse_to_search_values(iocs)
			logger.info("will make search num:{}".format(len(search_values)))
			logger.info("add search for {}".format(self.customer_name))
			results = self._add_search_to_customer(search_values)
			for each in results:
				self._post_to_splunk(each)
		else:
			logger.info("we cannot add new search config")

	# private

	def _parse_to_search_values(self, iocs):
		pri_order = ["sha256", "domain", "url", "ip" ]
		head = 0
		result = []
		for i in range(0, self.max_num):
			for each in pri_order:
				if len(iocs[each]) > head:
					ioc = iocs[each]
					result.append({ "type"   : each,
									"values" : ioc[head:head+25] })
				if len(result) >= self.max_num:
					break
			if len(result) >= self.max_num:
				break
			head += 25
		return result

	def _add_search_to_customer(self, search_values):
		result = []
		for each in search_values:
			if each["type"] == "sha256":
				query = _hxapi.make_queries_by_sha256(each["values"])
			elif each["type"] == "ip":
				query = _hxapi.make_queries_by_ipaddrs(each["values"])
			elif each["type"] == "domain":
				query = _hxapi.make_queries_by_hostnames(each["values"])
			elif each["type"] == "url":
				query = _hxapi.make_queries_by_url(each["values"])
			_id = _hxapi.set_new_enterprise_search(self.customer_name, query)
			each["search_id"] = _id
			each["status"] = "running"
			each["customer_name"] = self.customer_name
			each["product"] = self._PRODUCT
			result.append(each)
		return result

	def _work_for_current_search(self):
		def _make_error_response(customer_name, _id):
			return { "search_id" : _id, "customer_name" : customer_name,
					"status" : "finished", "hosts" : 0, "skipped" : 0,
					"result" : None, "message" : "error" }
		idlist = self._get_current_search_idlist()
		for each in idlist:
			_id = each["search_id"]
			customer_name = each["customer_name"]
			logger.info("check ID:{}".format(_id))
			if customer_name == self.customer_name:
				try:
					each_result = self._get_search_result(customer_name, _id)
					self._delete_search_config(customer_name, _id)
					del(each_result["_id"])
					each_result["search_id"] = _id
					each_result["customer_name"] = customer_name
					each_result["message"] = "success"
					each_result["status"] = "finished"
					each_result["product"] = self._PRODUCT
				except IOError as e:
					logger.info("error occurred by checking current search.")
					logger.exception(e)
					each_result = _make_error_response(customer_name, _id)
				except OSError as e:
					logger.info("error occurred by checking current search.")
					logger.exception(e)
					each_result = _make_error_response(customer_name, _id)
				self._post_to_splunk(each_result)
		current_num = self._get_other_search_num(self.customer_name)
		self.max_num = self.max_num - current_num
		logger.info("other search setting Num:{} we can use:{}".format(
			current_num, self.max_num))

	def _get_search_result(self, customer_name, _id):
		logger.info("get result search of {}".format(_id))
		result = _hxapi.get_result_enterprise_search(customer_name, _id)
		return result

	def _get_other_search_num(self, customer_name):
		result = _hxapi.get_result_enterprise_search(customer_name, None)
		return int(result["data"]["total"])

	def _delete_search_config(self, customer_name, _id):
		logger.info("delete search of {}".format(_id))
		_hxapi.delete_enterprise_search(customer_name, _id)

	def _get_current_search_idlist(self):
		q  = '| search index={} source={} {} earliest=-1w@w latest=now '.format(
				self.index, self.source, self.customer_name)
		q += '| spath search_id | spath status | spath customer_name'
		q += '| dedup search_id sortby _time desc '
		q += '| search NOT status=finished '
		q += '| table search_id,customer_name '
		q += '| search customer_name={} '.format(self.customer_name)
		result = self.splunk.raw_search(q)
		return result

def __main__():
	logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
	__main__()

