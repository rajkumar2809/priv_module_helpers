# -*- encoding:utf-8

import os, sys
import json

from monkey_tools.utils import time_util as _tu

class BuilderBase(object):
	_CLASS = None
	_KNOWN_FIELDS = []

	def __init__(self, helix_class=None):
		if helix_class:
			self.helix_class = helix_class
		else:
			self.helix_class = self._CLASS
		self.queries = {}
		self.unqueries = {}
		self._raw = None
	
	def add(self, field, value, op=None, is_not=False):
		if op is None:
			op=":"
		q = self.unqueries if is_not else self.queries
		if " " in value and not value.startswith('"'):
			value = '"{}"'.format(value)
		q["{}{}".format(field,op)] = value

	def set_from(self, value):
		if isinstance(value, int):
			value = self._to_helix_timeformat( value )
		self.add("meta_ts", value, ">")

	def set_to(self, value):
		if isinstance(value, int):
			value = self._to_helix_timeformat( value )
		self.add("meta_ts", value, "<")

	def set_time_around(self, value, diff=120):
		if isinstance(value, basestring):
			value = _tu.get_unix(value, _tu.UNIX)
		self.set_to(  value + diff)
		self.set_from(value - diff)

	def set_rawquery(self, value):
		self._raw = value

	def set_time_by_format(self, timestr):
		self.add("meta_ts", timestr)

	def to_query(self):
		q = [ "class:{}".format(self.helix_class) ]
		for k,v in self.queries.items():
			q.append("{}{}".format(k,v))
		for k,v in self.unqueries.items():
			q.append("NOT {}{}".format(k,v))
		if self._raw:
			q.append(self._raw)
		return " ".join(q)

	def get_known_fields(self):
		return self._KNOWN_FIELDS.keys()

	def parse_result(self, info):
		result = {"_raw" : json.dumps(info)}
		for k,v in self._KNOWN_FIELDS.items():
			path = v.split(".")
			value = self._parse_each_field(path, info)
			result[k] = value
		return result

	# private

	def _parse_each_field(self, path, info):
		results = []
		current = info
		for epath in path:
			if epath in current:
				current = current[epath]
			else:
				return ""
		return current

	def _to_helix_timeformat(self, value):
		value = _tu.get_time_from_unix(value, _tu.UNIX)
		return value.replace(" ", "T")

