# -*- coding: utf-8 -*-

import os,sys
import json, re, glob, logging

reload(sys)
sys.setdefaultencoding("utf-8")

import rm_helpers

_ANALYST_COMMENT_FLAG = "*result*"

logger = logging.getLogger()

def init_redmine(splunk_server, is_local=True):
	return rm_helpers.init_for_cbdefense(splunk_server, is_local)

def get_ticket_infos(splunk_server, idlist, is_local=True):
	redmine = init_redmine(splunk_server, is_local)
	result = {}
	for _id in idlist:
		try:
			ticket = get_ticket_info(redmine, _id)
			result[int(_id)] = ticket
		except IOError as e:
			result[int(_id)] = None
	return result

def get_ticket_info(redmine, _id):
	ticket = redmine.get_ticket(_id)
	if ticket:
		comment = []
		for rawcom in ticket["notes"]:
			each = rawcom.encode("utf8", errors="ignore")
			logger.debug("comment is {}".format(each))
			if each.startswith(_ANALYST_COMMENT_FLAG):
				comment.append(each.replace(_ANALYST_COMMENT_FLAG, "").strip())
		ticket["message"] = "\n".join(comment)
		return ticket
	else:
		return None

def main():
	logger.info("start test")
	_testid = [ 506146 ]
	result = get_ticket_infos("splunk-production02.dhsoc.jp", _testid, False)
	print json.dumps(result, indent=4)
	logger.info("end test")

if __name__ == '__main__':
	logging.basicConfig(level=logging.DEBUG)
	try:
		main()
	except Exception as e:
		logger.critical(e.message)
		logger.exception(e)

