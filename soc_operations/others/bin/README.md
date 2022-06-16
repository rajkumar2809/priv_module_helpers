[1] レポート作成
・ファイル
/opt/python_private_modules/priv_module_helpers/soc_operations/others/bin/call_ivr.py

・呼出し方
1) 
python スクリプト 顧客ID 
2) Splunkサーバ以外で実行する場合は、SplunkNameを指定する必要があります。
python スクリプト 顧客ID SplunkName

Note:
1)
SplunkNameは、選択する形になります。

・戻り値
1) 正常時
0
2) エラー時
1

・例
1)
python call_ivr.py TEST
2)
python call_ivr.py GDO1 splunk02

