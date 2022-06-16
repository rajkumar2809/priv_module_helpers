# -*- encoding:utf-8

import os, sys
import json
import base

class Builder(base.BuilderBase):
	_CLASS = "squid_http_proxy"
	_KNOWN_FIELDS = {
		"domain" : "_source.domain",
		"protocol" : "_source.protocol",
		"serverport" : "_source.serverport",
		"srcipv4" : "_source.srcipv4",
		"statuscode" : "_source.statuscode",
		"httpmethod" : "_source.httpmethod",
		"useragent" : "_source.useragent",
		"action" : "_source.action",
		"rawmsg" : "_source.rawmsg"
	}

def __simple_test__():
	obj = Builder()
	print obj.helix_class
	obj.set_time_around("2020-03-13 4:00:00", diff=28800)
	print obj.queries
	obj.add("srcipv4", "192.168.1.1", is_not=True)
	print obj.unqueries
	obj.set_rawquery("123 578 | fuga")
	print obj._raw
	print obj.to_query()
	print obj.get_known_fields()

if __name__ == '__main__':
	__simple_test__()
