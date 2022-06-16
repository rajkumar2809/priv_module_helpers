import os, sys, json
import re

_COM_ = []

class SplunkSearcher(object):
	_RETURN_DATA = []
	_NG_VALUE = {   "value"   : "ng_value",
					"product" : "ng_product",
					"user"    : "ng_user",
					"type"    : "ng_type" }
	_default = {
					"value"   : "test_value",
					"product" : "test_product",
					"user"    : "test_user",
					"type"    : "test_type",
					"data"    : "test_fuga"
				}

	def __default_(self):
		self._RETURN_DATA = [ { "_raw" : json.dumps(self._default) } ]

	def __init__(self, host, port, app, username, password):
		self.host = host
		self.port = port
		self.app  = app
		self.username = username
		self.password = password
		self.__default_()

	def search(self, query, exec_mode="blocking", max_count=100):
		_COM_.append({"method" : "search", "args" : {"query" : query, "exec_mode" : exec_mode, "max_count" : max_count}})
		ng_value   = "value\s*\=\s*\"{}\"".format(self._NG_VALUE["value"])
		ng_product = "product\s*\=\s*\"{}\"".format(self._NG_VALUE["product"])
		ng_user    = "user\s*\=\s*\"{}\"".format(self._NG_VALUE["user"])
		ng_type    = "type\s*\=\s*\"{}\"".format(self._NG_VALUE["type"])
		if re.search(ng_value, query) or re.search(ng_product, query) or re.search(ng_user, query) or re.search(ng_type, query):
			return []
		return list(self._RETURN_DATA)

	def _add_search_result(self, info):
		try:
			json.loads(info)
			self._RETURN_DATA.append(info)
		except ValueError as e:
			raise StandardError(
				"json value is incorrect format. Exception:{}".format(e.message))

