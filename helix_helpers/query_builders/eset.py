# -*- encoding:utf-8

import os, sys
import json
import base

class Builder(base.BuilderBase):
	_CLASS = "eset_raserver"
	_KNOWN_FIELDS = {
			"category" : "_source.category",
			"objecttype" : "_source.objecttype",
			"threat" : "_source.threat",
			"severity" : "_source.severity",
			"action" : "_source.action",
			"process" : "_source.process",
			"raw_pid" : "_source.raw_pid",
			"filename" : "_source.filename",
			"filepath" : "_source.filepath",
			"hash" : "_source.hash",
			"srcipv4" : "_source.srcipv4",
			"devicename" : "_source.devicename",
			"accountname" : "_source.accountname",
			"description" : "_source.description",
			"rawmsg" : "_source.rawmsg"
	}


	def __init__(self, helix_class=None):
		super(Builder, self).__init__(helix_class)
		self.add("eventname", "eset threat event")

def __simple_test__():
	obj = Builder()
	print obj.helix_class
	obj.set_time_around("2020-03-13 4:00:00", diff=28800)
	print obj.queries
	obj.add("srcipv4", "192.168.1.1", is_not=True)
	print obj.unqueries
	#obj.set_rawquery("123 578 | fuga")
	#print obj._raw
	print obj.to_query()

if __name__ == '__main__':
	__simple_test__()
