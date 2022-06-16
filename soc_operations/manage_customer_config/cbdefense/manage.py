# -*- coding: utf-8 -*-

import sys, os
import json, re, glob, argparse, configparser
import shutil, socket

reload(sys)
sys.setdefaultencoding("utf-8")

from monkey_tools.utils import logger_util
from monkey_tools.utils import file_util
from monkey_tools.utils.str_util import decrypto64 as dec64, encrypto64 as enc64

import procedure

_SPLUNK_HOST = {
	"splunk-production00.dhsoc.jp" : "splunk00.sgw001.dhsoc.jp",
	"splunk-production01.dhsoc.jp" : "splunk01.sgw001.dhsoc.jp",
	"splunk-production02.dhsoc.jp" : "splunk02.sgw001.dhsoc.jp",
	"splunk-production03.dhsoc.jp" : "splunk03.sgw001.dhsoc.jp",
	"splunk-production04.dhsoc.jp" : "splunk04.sgw001.dhsoc.jp" }


CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR = "{}/config".format(CURR_DIR)
_WORK_DIR = "{}/work".format(CURR_DIR)
_LOG_DIR  = "{}/log".format(CURR_DIR)
_BACKUP_DIR = "{}/backup".format(CURR_DIR)

_LOG_CONF = _CONF_DIR+"/log.conf"
_GEN_CONF = _CONF_DIR+"/config.json"
#_GEN_CONF = CURR_DIR+"/testdata/test_config.json"

_WORK_CURRENT_FILE = "current.tmp"

_TOP_HELP = """CarbonBlack-MDRユーザの追加作業をおこないます
"""
parser = argparse.ArgumentParser(description=_TOP_HELP)

def _set_argement():
	parser.add_argument('type',
		choices=['del', 'add'],
		help='del:削除作業, add:追加作業') 

def _parse_input_conf(file_name):
	config_ini = configparser.ConfigParser()
	config_ini.read(file_name, encoding='utf-8')
	return config_ini

def _get_all_customers(customer_file):
	customers = {}
	for each in glob.glob(customer_file):
		customer_id = ""
		sender = ""
		with open(each) as f:
			for l in f.readlines():
				l = l.strip()
				if l.startswith("顧客ID"):
					customer_id = l.split(":")[1]
				elif l.startswith("提供社"):
					sender = l.split(":")[1]
		if customer_id and sender:
			customers[customer_id] = {
				"customer" : customer_id,
				"sender"   : sender,
				"filename" : each }
		else:
			logger.error("{}は正しいファイル形式ではありません。".format(each))
			exit(0)
	return customers

def yes_no_input(msg=None):
	while True:
		if msg:
			choice = raw_input("{} [y/N]: ".format(msg)).lower()
		else:
			choice = raw_input("Please respond with 'yes' or 'no' [y/N]: ").lower()
		if choice in ['y', 'ye', 'yes']:
			return True
		elif choice in ['n', 'no']:
			return False

def _choice_target_customer(customers):
	if len(customers)>1:
		msg=", ".join(customers.keys())
		while True:
			res = raw_input("複数の対象が存在します。作業対象を入力して下さい。[{}]:".format(msg))
			if res in customers:
				logger.info("{}が入力されました。".format(res))
				break
			else:
				logger.info("{}が入力されました。対象ではありません。".format(res))
		target=customers[res]
	else:
		target=customers[customers.keys()[0]]
	logger.info("対象は{}となります。".format(target["customer"]))
	return target

def _has_current(work_type):
	work_dir = "{}/{}".format(_WORK_DIR, work_type)
	return os.path.exists("{}/{}".format(work_dir, _WORK_CURRENT_FILE))

def _write_current(msg, work_type):
	work_dir = "{}/{}".format(_WORK_DIR, work_type)
	with open("{}/{}".format(work_dir, _WORK_CURRENT_FILE), "w") as wf:
		wf.write(msg)

def _copy_all_config_to_backup(config):
	if os.path.exists(_BACKUP_DIR+"/credentials"):
		shutil.rmtree(_BACKUP_DIR+"/credentials")

	shutil.copyfile(config["splunk_devices"],
		_BACKUP_DIR+"/cb_devices.csv")
	shutil.copyfile(config["input_conf"],
		_BACKUP_DIR+"/inputs.conf")
	shutil.copyfile(config["cbapp_creds_share"],
		_BACKUP_DIR+"/cbdefense.json")
	shutil.copytree(config["cbapp_creds_eachdir"],
		_BACKUP_DIR+"/credentials")

def _copy_all_config(work_type, config):
	work_conf_dir = "{}/{}/config".format(_WORK_DIR, work_type)
	shutil.copyfile(config["splunk_devices"],
		work_conf_dir+"/cb_devices.csv")
	shutil.copyfile(config["input_conf"],
		work_conf_dir+"/inputs.conf")
	shutil.copyfile(config["cbapp_creds_share"],
		work_conf_dir+"/cbdefense.json")
	shutil.copytree(config["cbapp_creds_eachdir"],
		work_conf_dir+"/credentials")

def _init_work(args, config):
	if not os.path.exists(_WORK_DIR):
		os.mkdir(_WORK_DIR)
	if   args.type == "del":
		customers = _get_all_customers(config["deluser_texts"])
	elif args.type == "add":
		customers = _get_all_customers(config["adduser_texts"])
	target = _choice_target_customer(customers)
	res=yes_no_input("対象が問題なければ[y]を入力して下さい。作業を開始します。")
	if res is False:
		logger.info("Noが選択されました。作業は停止します")
		exit(0)
	work_dir = "{}/{}".format(_WORK_DIR, args.type)
	res=yes_no_input("以下作業フォルダを空にします。問題なければ[y]を入力してください。\n{}".format(work_dir))
	if res is False:
		logger.info("Noが選択されました。作業は停止します")
		exit(0)
	if os.path.exists(work_dir):
		shutil.rmtree(work_dir)
	os.mkdir(work_dir)
	os.mkdir(work_dir+"/config")
	with open(work_dir+"/target.json", "w") as wf:
		json.dump(target, wf, indent=4)
	_copy_all_config(args.type, config)
	shutil.move(target["filename"], work_dir+"/target.txt")
	return target

def _parse_cbapi_conf_current(config):
	results = {}
	with open(config["cbapp_creds_share"]) as f:
		creds = json.load(f)
	for each in creds:
		each["file_name"] = "cbdefense.json"
		each["is_share"]  = True
		results[each["customer_name"]]=each
	for each in glob.glob(config["cbapp_creds_eachdir"]+"/*.json"):
		file_name = each.split("/")[-1]
		with open(each) as f:
			each = json.load(f)
		each["file_name"] = file_name
		each["is_share"]  = False
		results[each["customer_name"]]=each
	return results

def _parse_cbapi_conf(work_dir):
	results = {}
	with open("{}/config/cbdefense.json".format(work_dir)) as f:
		creds = json.load(f)
	for each in creds:
		each["file_name"] = "cbdefense.json"
		each["is_share"]  = True
		results[each["customer_name"]]=each
	for each in glob.glob("{}/config/credentials/*.json".format(work_dir)):
		file_name = each.split("/")[-1]
		with open(each) as f:
			each = json.load(f)
		each["file_name"] = file_name
		each["is_share"]  = False
		results[each["customer_name"]]=each
	return results

def _parse_customer_csv(customer_csv):
	customers = file_util.parse_csv(customer_csv)
	for each in customers:
		for key in each.keys():
			newkey = key.strip()
			each[newkey] = each[key]
	return customers

def _get_index(work_dir, customer_name):
	customers = _parse_customer_csv(work_dir+"/config/cb_devices.csv")
	for each in customers:
		if each["customer_name"] == customer_name:
			index = "cbdefense_threat_alert_{}".format(each["appliance_id"].strip())
			return index
	logger.error("devices.csvに対象ユーザが登録されていません。")
	exit(0)

def _get_splunk_name():
	hostname = socket.gethostname()
	if hostname in _SPLUNK_HOST:
		return _SPLUNK_HOST[hostname]
	else:
		return "unknown({})".format(hostname)

def _diff_inputs_conf(before, after):
	before = _parse_input_conf(before)
	after  = _parse_input_conf(after)
	del_list = []
	add_list = []
	for each in before.keys():
		if not each in after:
			each = before[each]
			disabled = each.get("disabled")
			if disabled is None:
				disabled = 1
			del_list.append({   "index"    : each["index"],
								"disabled" : str(disabled) })
	for each in after.keys():
		if not each in before:
			each = after[each]
			disabled = each.get("disabled")
			if disabled is None:
				disabled = 1
			add_list.append({   "index"    : each["index"],
								"disabled" : str(disabled) })
	enabled  = []
	disabled = []
	for each in before.keys():
		if each in after:
			before_disabled = before[each].get("disabled")
			after_disabled  = after[each].get("disabled")
			if not before_disabled == after_disabled:
				each_index = before[each]["index"]
				if str(before_disabled) == "1":
					enabled.append({
						"index" : each_index, "disabled" : "0" })
				elif str(before_disabled) == "0" or before_disabled is None:
					if str(after_disabled) == "1":
						disabled.append({
							"index" : each_index, "disabled" : "1" })
	return {"add"     : add_list, "del" : del_list,
			"enabled" : enabled,  "disabled" : disabled }

def _check_input_add(index, config, work_dir):
	cfg_before = "{}/config/{}".format(work_dir, "inputs.conf")
	cfg_after  = config["input_conf"]
	result = _diff_inputs_conf(cfg_before, cfg_after)
	if len(result["del"]) is not 0:
		logger.error("入力設定の削除がされています。")
		print json.dumps(result["del"], indent=4)
	if len(result["enabled"]) is not 0:
		logger.error("入力設定の有効化がされています。")
		print json.dumps(result["enabled"], indent=4)
	if len(result["disabled"]) is not 0:
		logger.error("入力設定の無効化がされています。")
		print json.dumps(result["disabled"], indent=4)
	if len(result["add"]) is 0:
		logger.error("入力設定の追加がされていません。")
	else:
		for each in result["add"]:
			if each["index"] != index:
				logger.error("別ユーザ[{}]で入力設定の追加がされてます。".format(each["index"]))
	res = yes_no_input("設定内容に問題がなければ、yを入力して下さい。")
	if res is False:
		logger.error("Noが押されました。作業を終了します。")
		print json.dumps(result, indent=4)
		exit(0)
	return result

def _check_input_delete(index, config, work_dir):
	cfg_before = "{}/config/{}".format(work_dir, "inputs.conf")
	cfg_after  = config["input_conf"]
	result = _diff_inputs_conf(cfg_before, cfg_after)
	if len(result["add"]) is not 0:
		logger.error("入力設定の追加がされています。")
		print json.dumps(result["add"], indent=4)
	if len(result["enabled"]) is not 0:
		logger.error("入力設定の有効化がされています。")
		print json.dumps(result["enabled"], indent=4)
	if len(result["disabled"]) is not 0:
		logger.error("入力設定の無効化がされています。")
		print json.dumps(result["disabled"], indent=4)
	if len(result["del"]) is 0:
		logger.error("入力設定の削除がされていません。")
	else:
		for each in result["del"]:
			if each["index"] != index:
				logger.error("別ユーザ[{}]で入力設定の削除がされてます。".format(each["index"]))
	res = yes_no_input("設定内容に問題がなければ、yを入力して下さい。")
	if res is False:
		logger.error("Noが押されました。作業を終了します。")
		print json.dumps(result, indent=4)
		exit(0)
	return result

def _diff_devices_conf(before, after):
	add_list = []
	del_list = []
	for each in before:
		customer_name = each["customer_name"]
		appliance_id  = each["appliance_id"]
		is_match = False
		for chk in after:
			if( chk["customer_name"] == customer_name and
				chk["appliance_id"]  == appliance_id ):
				is_match = True
		if is_match is False:
			del_list.append({   "customer_name" : customer_name,
								"appliance_id" : appliance_id })
	for each in after:
		customer_name = each["customer_name"]
		appliance_id  = each["appliance_id"]
		is_match = False
		for chk in before:
			if( chk["customer_name"] == customer_name and
				chk["appliance_id"]  == appliance_id ):
				is_match = True
		if is_match is False:
			add_list.append({   "customer_name" : customer_name,
								"appliance_id" : appliance_id })
	return { "add" : add_list, "del" : del_list }

def _diff_cbapi(work_dir, config):
	before = _parse_cbapi_conf(work_dir)
	after  = _parse_cbapi_conf_current(config)
	add_list = []
	del_list = []
	for each in before.keys():
		if not each in after:
			info = before[each]
			del_list.append( {
				"customer_name" : info["customer_name"],
				"appliance_id"  : info["customer_id"] } )
	for each in after.keys():
		if not each in before:
			info = after[each]
			add_list.append( {
				"customer_name" : info["customer_name"],
				"appliance_id"  : info["customer_id"] } )
	return { "add" : add_list, "del" : del_list }

def _check_cbapi_add(customer_name, index, config, work_dir):
	result = _diff_cbapi(work_dir, config)
	print json.dumps(result, indent=4)
	if len(result["del"])>0:
		logger.error("ユーザーの削除がされています。")
		print json.dumps(result["add"], indent=4)
	if len(result["add"]) is 0:
		logger.error("API設定の追加がされていません。")
	else:
		for each in result["add"]:
			if not each["customer_name"] == customer_name:
				each_customer = each["customer_name"]
				logger.error("対象以外のユーザー[{}]追加がされています。".format(each_customer))
	res = yes_no_input("設定内容に問題がなければ、yを入力して下さい。")
	if res is False:
		logger.error("Noが押されました。作業を終了します。")
		print json.dumps(result, indent=4)
		exit(0)
	return result

def _check_cbapi_delete(customer_name, index, config, work_dir):
	result = _diff_cbapi(work_dir, config)
	print json.dumps(result, indent=4)
	if len(result["add"])>0:
		logger.error("ユーザーの追加がされています。")
		print json.dumps(result["add"], indent=4)
	if len(result["del"]) is 0:
		logger.error("ユーザーの削除がされていません。")
	else:
		for each in result["del"]:
			if not each["customer_name"] == customer_name:
				each_customer = each["customer_name"]
				logger.error("対象以外のユーザー[{}]追加がされています。".format(each_customer))
	res = yes_no_input("設定内容に問題がなければ、yを入力して下さい。")
	if res is False:
		logger.error("Noが押されました。作業を終了します。")
		print json.dumps(result, indent=4)
		exit(0)
	return result

def _check_customer_add(customer_name, index, config, work_dir):
	after  = _parse_customer_csv(config["splunk_devices"])
	before = _parse_customer_csv("{}/config/cb_devices.csv".format(work_dir))
	result = _diff_devices_conf(before, after)
	if len(result["del"])>0:
		logger.error("ユーザーの削除がされています。")
		print json.dumps(result["del"], indent=4)
	if len(result["add"]) is 0:
		logger.error("ユーザーの追加がされていません。")
	else:
		for each in result["add"]:
			if not each["customer_name"] == customer_name:
				each_customer = each["customer_name"]
				logger.error("対象以外のユーザー[{}]追加がされています。".format(each_customer))
	res = yes_no_input("設定内容に問題がなければ、yを入力して下さい。")
	if res is False:
		logger.error("Noが押されました。作業を終了します。")
		print json.dumps(result, indent=4)
		exit(0)
	return result

def _check_customer_delete(customer_name, index, config, work_dir):
	after  = _parse_customer_csv(config["splunk_devices"])
	before = _parse_customer_csv("{}/config/cb_devices.csv".format(work_dir))
	result = _diff_devices_conf(before, after)
	if len(result["add"])>0:
		logger.error("ユーザーの追加がされています。")
		print json.dumps(result["add"], indent=4)
	if len(result["del"]) is 0:
		logger.error("ユーザーの削除がされていません。")
	else:
		for each in result["del"]:
			if not each["customer_name"] == customer_name:
				each_customer = each["customer_name"]
				logger.error("対象以外のユーザー[{}]削除がされています。".format(each_customer))
	res = yes_no_input("設定内容に問題がなければ、yを入力して下さい。")
	if res is False:
		logger.error("Noが押されました。作業を終了します。")
		print json.dumps(result, indent=4)
		exit(0)
	return result

def _get_cbapi_conf(customer, index, work_dir):
	conf_all = _parse_cbapi_conf(work_dir)
	print customer
	print conf_all.keys()
	return conf_all.get(customer)

def _check_index_duplication(index, work_type):
	work_dir = "{}/{}".format(_WORK_DIR, work_type)
	cfg = _parse_input_conf(work_dir+"/config/inputs.conf")
	for key in cfg.keys():
		each = cfg[key]
		if each.get("index") == index:
			return True
	return False

def _define_index(customer_name, work_type):
	work_dir = "{}/{}".format(_WORK_DIR, work_type)
	indexfile = work_dir+"/index.json"
	if os.path.exists(indexfile):
		logger.info("既存のindexファイルを読み込みます")
		with open(indexfile) as f:
			index=json.load(f)
		return index["appliance_id"], index["index"]
	while True:
		appid = raw_input("追加ユーザのappliance_id(indexの末尾)を入力して下さい:")
		index = "cbdefense_threat_alert_{}".format(appid)
		if _check_index_duplication(index, work_type):
			logger.info("index:{}はすでに存在します。".format(index))
			continue
		res = yes_no_input("index情報:{}({})\nで問題なければyを入力して下さい。".format(appid, index))
		if res:
			break
	with open(indexfile, "w") as wf:
		json.dump({"index":index, "appliance_id":appid}, wf, indent=4)
	return appid, index


def del_user(args, config):
	hostname = _get_splunk_name()
	work_dir = "{}/{}".format(_WORK_DIR, args.type)
	_init = not(_has_current(args.type))
	if not _init:
		_init = yes_no_input("作業中の情報があります。新しく始めますか?")
	if _init:
		target = _init_work(args, config)
		_write_current("0.complete_init", args.type)
	else:
		with open(work_dir+"/target.json") as f:
			target = json.load(f)
	# indexの取得
	index = _get_index(work_dir, target["customer"])

	# 入力設定の削除
	res = raw_input(procedure.delete_input.format(hostname, index))
	res_input_delete = _check_input_delete(index, config, work_dir)
	_write_current("1.delete_input", args.type)

	# cb_devices.csvから削除
	res = raw_input(procedure.delete_customer_csv.format(target["customer"], index))
	res_customer_delete = _check_customer_delete(target["customer"], index, config, work_dir)
	_write_current("2.delete_customer", args.type)

	# Splunk内に保管しているCBのAPI設定を削除
	cbapi_conf =  _get_cbapi_conf(target["customer"], index, work_dir)
	if cbapi_conf is None:
		logger.error("対象ユーザの設定がすでに存在しません。")
		res_customer_delete = "削除対象のユーザなし"
	else:
		if cbapi_conf["is_share"]:
			res = raw_input(procedure.delete_cbapi_conf_by_share.format(target["customer"], index))
		else:
			res = raw_input(procedure.delete_cbapi_each_file.format(cbapi_conf["file_name"], target["customer"], index))
		res_cbapi_delete = _check_cbapi_delete(target["customer"], index, config, work_dir)
	_write_current("3.delete_api_creds", args.type)
	result = {  "input"   : res_input_delete,
				"devices" : res_customer_delete,
				"cbapi"   : res_cbapi_delete }
	with open("{}/results.json".format(work_dir), "w") as wf:
		json.dump(result, wf, indent=4)
	_copy_all_config_to_backup(config)
	return result

def add_user(args, config): #TODO
	hostname = _get_splunk_name()
	work_dir = "{}/{}".format(_WORK_DIR, args.type)
	_init = not(_has_current(args.type))
	if not _init:
		_init = yes_no_input("作業中の情報があります。新しく始めますか?")
	if _init:
		target = _init_work(args, config)
		_write_current("0.complete_init", args.type)
	else:
		with open(work_dir+"/target.json") as f:
			target = json.load(f)
	logger.info("{}の追加作業を開始します。".format(target["customer"]))
	appid, index = _define_index(target["customer"], args.type)
	logger.info("追加対象のindexは{}({})となります。".format(index, appid))

	# indexの作成
	res = raw_input(procedure.add_index.format(hostname, index))
	_write_current("1.create_index", args.type)

	# cb_devices.csvへの追加
	restapi_id  = raw_input("MDR_API2のAPI_IDを入力して下さい:")
	restapi_key = raw_input("MDR_API2のAPI_KEYを入力して下さい:")
	org_key     = raw_input("APIのORG_KEYを入力して下さい:")
	cb_hostname = raw_input("CarbonBlackログオン時のホスト名を入力して下さい(例:defense-prod05.conferdeploy.net):")
	cb_hostname_base = cb_hostname.replace("defense-", "")
	res = raw_input(procedure.add_customer.format(target["customer"], appid, restapi_id, target["sender"], cb_hostname))
	res_customer_add = _check_customer_add(target["customer"], index, config, work_dir)
	_write_current("2.add_customer", args.type)

	# CBのAPI設定を追加
	token="{}/{}".format(restapi_key, restapi_id)
	token=enc64(token)
	apiconf = { "customer_id" : appid,
				"customer_name" : target["customer"],
				"host" : cb_hostname_base,
				"port" : 443,
				"tokens" : { "rest" : token, "lr" : token, "ex" : token },
				"org_key" : org_key }
	str_apiconf = json.dumps(apiconf, indent=4)
	res = raw_input(procedure.add_cbapi.format(target["customer"], str_apiconf))
	res_cbapi_add = _check_cbapi_add(target["customer"], index, config, work_dir)
	_write_current("3.add_cbapi", args.type)

	# 入力設定を追加
	res = raw_input(procedure.add_input.format(hostname, "api-"+cb_hostname_base, appid, index))
	res_input_add = _check_input_add(index, config, work_dir)
	_write_current("4.add_input", args.type)
	result = {  "input"   : res_input_add,
				"devices" : res_customer_add,
				"cbapi"   : res_cbapi_add }
	with open("{}/results.json".format(work_dir), "w") as wf:
		json.dump(result, wf, indent=4)
	_copy_all_config_to_backup(config)
	return result

def main():
	_set_argement()
	args = parser.parse_args()
	with open(_GEN_CONF) as f:
		config = json.load(f)
	if args.type == "add":
		logger.info("ユーザ追加作業を開始します。")
		result = add_user(args, config)
		logger.info("ユーザ追加作業を完了しました。")
	elif args.type == "del":
		logger.info("ユーザ削除作業を開始します。")
		result = del_user(args, config)
		print "=="*16
		print json.dumps(result, indent=4)
		print "=="*16
		logger.info("ユーザ削除作業を完了しました。")
	else:
		logger.error("不明な入力:{}".format(args.type))

if __name__ == '__main__':
	os.chdir(CURR_DIR)
	logger_util.init_conf(_LOG_CONF)
	logger = logger_util.get_standard_logger("manage_cusomter_config")
	logger_util.change_permission_log_file(_LOG_DIR)
	try:
		main()
	except Exception as e:
		logger.exception(e)

