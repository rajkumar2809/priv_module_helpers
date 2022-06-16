# -*- coding: utf-8 -*-

import os, sys

import urllib, urllib2, ssl, json, re, copy
from monkey_tools.utils import rest_util

dirpath = os.path.dirname( os.path.abspath(__file__) )
_CONF_PATH = dirpath+"/config"

class SplunkLogSender(object):
	_PORT = 8089
	_URI  = '/services/receivers/simple'
	_CONF = None

	@classmethod
	def init_splunk_by_cfg_file(cls, splunk_name, cfg_dir=None, by_local=True):
		cfg_dir = _CONF_PATH
		if "." in splunk_name:
			cfg_name = splunk_name.split(".", 1)[0]
		else:
			cfg_name = splunk_name
		with open("{}/{}.json".format(cfg_dir, cfg_name)) as f:
			cfg = json.load(f)
		if by_local:
			cfg["host"] = "127.0.0.1"
		return cls(
			cfg["host"], cfg["username"], cfg["password"], port=cfg["port"])

	def __init__(self, hostname, username, password, resource=None, port=None):
		"""
		[str]hostname, [str]username, [str]password,
		[str]resource(startswith</>)
		"""
		assert isinstance(hostname, basestring), "hostname must be str or unicode"
		assert isinstance(username, basestring), "username must be str or unicode"
		assert isinstance(password, basestring), "password must be str or unicode"
		self.hostname = hostname
		self.username = username
		self.password = password
		self.params = {}
		if resource:
			assert isinstance(resource, str) or isinstance(resource, unicode), "resource must be str or unicode"
			self.resource = resource
		else:
			self.resource = self._URI
		if port:
			assert isinstance(port, int), "port must be int type"
			self.port = port
		else:
			self.port = self._PORT
	
	def make_param_dict(self, index, source, sourcetype=None):
		"""
		[str]index, [str]source, [str]sourcetype -> dict
		"""
		assert isinstance(index, basestring), "index must be use str or unicode"
		assert len(index)>0, "index is empty string"
		assert isinstance(source, basestring), "source must be use str or unicode"
		assert len(source)>0, "source is empty string"
		data = {
				"index" : index,
				"source" : source }
		if sourcetype is not None:
			assert isinstance(sourcetype, str) or isinstance(sourcetype, unicode), "sourcetype must be use str or unicode"
			assert len(sourcetype)>0, "sourcetype is empty string"
			data["sourcetype"]=sourcetype
		return data

	def build_url_for_splunk_post(self, data_type):
		"""
		need to call init_params at same data_type
		[str]data_type -> str
		"""
		params = self.get_params(data_type)
		assert params, "init for data_type:{} is not yet."
		return rest_util.build_url(self.hostname, resource=self._URI, port=self.port, params=params)

	def init_params(self, data_type, index, source, sourcetype=None):
		"""
		if call this at multi times with same data_type, prev data is overwritten.
		[str]data_type, [str]index, [str]source, [str]sourcetype
		"""
		assert isinstance(data_type, basestring), "data_type must be use str or unicode"
		assert len(data_type)>0, "data_type is empty string"
		self.params[data_type]=self.make_param_dict(index, source, sourcetype)

	def has_params(self, data_type):
		return data_type in self.params

	def get_params(self, data_type):
		"""
		[str]data_type -> dict(if init_params for this data_type is not yet, None)
		"""
		if data_type in self.params:
			return self.params[data_type]
		else:
			return None

	def post_data(self, data_type, data, headers=None):
		"""
		[str]data_type, [str]data(json format), [dict] headers(default is None)
		-> return [] response
		"""
		assert isinstance(data, basestring), "post data is accepted only string"
		assert len(data) > 0, "json data is empty."
		try:
			json.loads(data)
		except ValueError as e:
			assert("json data is malformed.")
		url = self.build_url_for_splunk_post(data_type)
		return rest_util.send_post(url, data, self.username, self.password, headers)

