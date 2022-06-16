# -*- coding:utf-8 -*-

import logging
from logging import getLogger, StreamHandler, Formatter
logger = getLogger("LogTest")
logger.setLevel(logging.DEBUG)
stream_handler = StreamHandler()
stream_handler.setLevel(logging.DEBUG)
handler_format = Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
stream_handler.setFormatter(handler_format)
logger.addHandler(stream_handler)

import subprocess as sp

_CHROME_ = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' #for MAC

#from connectors.micky_app_api import micky_api_ex

from priv_module_helpers.soc_operations.others import helper
helper.logger = logger

class test_sp(object):
	STDOUT = "TEST_STDOUT"
	_COM = None
	_WITH_ERR = False

	@classmethod
	def check_output(cls, command, stderr=None):
		cls._COM = command
		if cls._WITH_ERR:
			raise test_sp.CalledProcessError()
		return 0

	class CalledProcessError(sp.CalledProcessError):
		pass

_USE_MOCK = False

if _USE_MOCK:
	helper.sp = test_sp

def _test_cbdefense():
	args = {
		"alert_datetime" : "2019/12/18 07:58:48",
		"customer_name"  : "DGH1",
		"product"        : "cbdefense",
		"alert_type"     : "malware",
		"alert_id"       : "IWR0ORYF",
		"severity"       : "高",
		"ticket_no"      : "30857",
		"device_name"    : "DH-SOC-Win10",
		"policy"         : "DH_MDR_POC",
		"device_id"      : "8995283",
		"exec_user"      : None,
		"splunk_name"    : "splunk00",
		"_python"        : None
	}
	helper.boot_autorun(**args)

def _test_stellar():
	args = {
		"alert_datetime" : "2020/10/02 11:02:35",
		"customer_name"  : "JCM1",
		"product"        : "stellar",
		"alert_id"       : "dFkE53QBxFBxxfEQQ29z",
		"severity"       : "中",
		"ticket_no"      : "34873",
		"exec_user"      : None,
		"splunk_name"    : "splunk00",
		"_python"        : None
	}
	result = helper.boot_autorun(**args)
	if _USE_MOCK:
		if isinstance(test_sp._COM, list):
			print " ".join(test_sp._COM)
		else:
			print test_sp._COM
	else:
		print result 

def _test_func_make_args(with_base64=True):
	args = {
		"alert_datetime" : "2020/10/02 11:02:35",
		#"customer_name"  : "JCM1",
		"product"        : "stellar",
		"alert_id"       : "dFkE53QBxFBxxfEQQ29z",
		"severity"       : "高",
		"ticket_no"      : "30857",
	}
	print helper.make_args(with_base64=with_base64, **args)

if __name__ =="__main__":
	print helper.sp
	#unittest.main()
	#_test_cbdefense()
	#_test_func_make_args()
	_test_stellar()


