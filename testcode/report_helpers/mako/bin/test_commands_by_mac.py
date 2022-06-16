# -*- encoding:utf-8 -*-

import os, sys
import base64

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/../../../mako"
sys.path.append(MODULE_TOP)

import priv_module_helpers.report_helpers.mako.helper as com

_OUTPUT_ = "/tmp/output.html"
_TESTFILE_ = "../testfile/helix_squid2.json"

b64_data='ewogICJhbGVydF9pZCI6ICI1ZDIyY2EyNWEyYjY4MDVlZjIwMDAwMDQiLAogICJjb25maWRlbmNlX2pwbiI6ICLpq5giLAogICJtZXNzYWdlIiA6ICJBUEZFTEwgQkFDS0RPT1IgW1VSSV0iLAogICJkZXNjcmlwdGlvbiI6ICJBcGZlbGwgaXMgYW4gb3BlbiBzb3VyY2UgbWFjT1MgcG9zdC1leHBsb2l0YXRpb24gZnJhbWV3b3JrLiBUaGlzIHJ1bGUgZGV0ZWN0cyB0aGUgcHJlc2VuY2Ugb2YgVVJJIHBhdGhzIHVzZWQgYnkgQXBmZWxsJ3MgY29tbWFuZCBhbmQgY29udHJvbCBzZXJ2ZXIuIiwKICAiZGV0ZWN0X3RpbWUiOiAiMjAxOS8wNy8wOCAwNDo0NTo0OSIsCiAgImRvbWFpbiI6ICJhdHRhY2tlci50ZWNoLW9zaGliYS5jb20iLAogICJldmVudENvdW50IjogIjEiLAogICJmaXJzdEV2ZW50QXQiOiAiMjAxOS8wNy8wOCAwNDo0MzoxOCIsCiAgImZpcnN0U2VlbiI6ICJZZXMiLAogICJodHRwbWV0aG9kIjogImdldCIsCiAgImtpbGxjaGFpbiI6ICI2IC0gQzIiLAogICJsaW5ldHlwZSI6ICJyZXBvcnRkYXRhIiwKICAicmVtZWRpYXRpb24iOiAi5o6o5aWo5a++5b+c44Gu44OG44K544OI44Gn44GZXG7vvJLooYznm67jgafjgZkiLAogICJyaXNrX2pwbiI6ICLnt4rmgKUiLAogICJzZXZlcml0eV9qcG4iOiAi6auYIiwKICAic3JjX2hvc3QiOiAiMTkyLjE2OC4xMjkuMSIsCiAgInN0YXR1c2NvZGUiOiAiMjAwIiwKICAic3VtbWFyeSI6ICLjgrXjg57jg6rmg4XloLHjga7jg4bjgrnjg4jjgafjgZnjgIJcbu+8kuihjOebruOBp+OBmSIsCiAgInRhZ3MiOiAiYXBmZWxsLENvbW1hbmQgYW5kIENvbnRyb2wsU3RhbmRhcmQgQXBwbGljYXRpb24gTGF5ZXIgUHJvdG9jb2wsVDEwNzEsZmFhcy1oaWdoLXByaW9yaXR5LG1kLWFjdGlvbiIsCiAgInVyaSI6ICIvYXBpL3YxMjMuNDU2Ny90YXNrcy9jYWxsYmFjay83ODkwL25leHR0YXNrIiwKICAidXNlcmFnZW50IjogImN1cmwvNy41NC4wIgp9Cg=='
data=base64.b64decode(b64_data)

def test_make():
	res=com.analyst_report(b64_data, _b64=True, _python='/usr/local/bin/python')
	#res=com.analyst_report(data, _python='/usr/local/bin/python')
	#res=com.analyst_report(_TESTFILE_, _file=True, _python='/usr/local/bin/python')
	#res=com.analyst_report(b64_data, _b64=True, _python='/usr/local/bin/python')
	print res

def test_write():
	#res=com.write_analyst_report(b64_data, _OUTPUT_, _b64=True, _python='/usr/local/bin/python')
	#res=com.write_analyst_report(data, _OUTPUT_, _python='/usr/local/bin/python')
	res=com.write_analyst_report(_TESTFILE_, _OUTPUT_, _file=True, _python='/usr/local/bin/python')
	#res=com.write_analyst_report(b64_data, _OUTPUT_, _b64=True, _python='/usr/local/bin/python')
	print res

try:
	test_write()
except Exception as e:
	print "error occurred"
	raise e

