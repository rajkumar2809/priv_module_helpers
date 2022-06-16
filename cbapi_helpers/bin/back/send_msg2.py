# -*- coding: utf-8 -*-

import sys, os
import argparse
from priv_module_helpers.cbapi_helpers import cb_api_helper as api
from monkey_tools.utils import logger_util

reload(sys)
sys.setdefaultencoding("utf-8")

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/.."
sys.path.append(PJ_TOP)
CONF_DIR  = PJ_TOP+"/config"
LOG_DIR   = PJ_TOP+"/log"
_LOG_CONF = CONF_DIR+"/log/send_msg2.conf"

def get_lrapi(customer_info):
	return api.init_by_cfg_file(customer_info, "lr")

_MSG_ = u"本端末はマルウェアに感染した恐れのあるため、ネットワークから隔離されます。"
_COM_ = "msg.exe * /server:localhost /TIME:0 \"{}\""
#_TESTID_ = "10463299"

parser = argparse.ArgumentParser(description="send message command by live response")
parser.add_argument('customer_name', help="customer name of dhsoc splunk config")
parser.add_argument('device_id', help="device id for send command")
parser.add_argument('-message', default=None, help="message for send command")
parser.add_argument('-with_disable_sleep', default=False, help="message send with disable sleep.")
args = parser.parse_args()
customer_name = args.customer_name
device_id = args.device_id
msg_data = args.message if args.message else _MSG_
with_disable_sleep = args.with_disable_sleep
_COM_DISABLE_SLEEP = "powercfg /change standby-timeout-ac 0"

def main(logger):
	logger.info("start send command")
	logger.info("get api module for {}".format(customer_name))
	api = get_lrapi(customer_name)
	command = _COM_.format(msg_data.encode('utf-8'))
	if with_disable_sleep:
		command = [ command, _COM_DISABLE_SLEEP ]
	logger.info("send command[ {} ] to {}".format(command, device_id))
	flag = api.lr_send_command(device_id, command)
	logger.info("finish to send command. result:{}".format(flag))
	if flag:
		print 0
	else:
		print 1

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("live_response_command")
	logger_util.change_permission_log_file(LOG_DIR)
	try:
		main(logger)
	except Exception as e:
		logger.error("fail with exception")
		logger.exception(e)
		print 1

