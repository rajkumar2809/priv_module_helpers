# -*- coding: utf-8 -*-
#TODO: deprecated

import sys, os
import argparse
import cb_api_helper as api
from monkey_tools.utils import logger_util

CURR_DIR   = os.path.dirname( os.path.abspath(__file__) )
_CONF_PATH = CURR_DIR+"/config"
#_LOG_CONF = _CONF_PATH+"/log.conf"
_LOG_CONF  = _CONF_PATH+"/commands.conf"


def get_lrapi(customer_info):
	return api.init_by_cfg_file(customer_info, "lr")

_MSG_ = u"本端末はマルウェアに感染した恐れのあるため、ネットワークから隔離されます。"
_COM_ = "msg.exe /TIME:0 1 \"{}\""
#_TESTID_ = "10463299"

parser = argparse.ArgumentParser(description="send message command by live response")
parser.add_argument('customer_name', help="customer name of dhsoc splunk config")
parser.add_argument('device_id', help="device id for send command")
parser.add_argument('-message', default=None, help="message for send command")
args = parser.parse_args()
customer_name = args.customer_name
device_id = args.device_id
msg_data = args.message if args.message else _MSG_

def main(logger):
	try:
		logger.info("start send command")
		logger.info("get api module {}".format(customer_name))
		api = get_lrapi(customer_name)
		command = _COM_.format(msg_data.encode('utf-8'))
		logger.info("send command[ {} ] to {}".format(command, device_id))
		flag = api.lr_send_command(device_id, command)
		logger.info("finish to send command. result:{}".format(flag))
		if flag:
			print 0
		else:
			print 1
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("live_response_command")
	try:
		main(logger)
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1
