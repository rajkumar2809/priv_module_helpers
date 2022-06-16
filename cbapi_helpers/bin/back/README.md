各コマンドの説明

[1] デバイス検索
・ファイル
/opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/search_device.py

・呼出し方
1)
python スクリプト {customerId} -ipaddr=x.x.x.x
2)
python スクリプト {customerId} -hostname=YYYYYYY
※hostnameでも検索できるようにしてます。

・戻り値
1) 正常時
[
  { "device_id" : "xxxxxxxx", "policy" : "test_policy", "device_name" : "nameX" },
  { "device_id" : "yyyyyyyy", "policy" : "test_policy", "device_name" : "nameY" }
]

2) エラー時
1

・例
python /opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/search_device.py DGH1 -ipaddr=1.1.1.1                                                                   

[2] 隔離メッセージ送信
・ファイル
/opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/send_msg.py

・呼出し方
1)
python スクリプト {customerId} {deviceId}
2)
python スクリプト {customerId} {deviceId} -message=xxxxxxxxxxxxx
※messageのデフォルトは以下。
　本端末はマルウェアに感染した恐れのあるため、ネットワークから隔離されます。

・戻り値
1) 正常時
0
2) エラー時
1

・例
python /opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/send_msg.py DGH1 01234567 -message="Hello"

[2] デバイス隔離実施
・ファイル
/opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/quarantine.py

・呼出し方
1)
python スクリプト {customerId} {deviceId}
2)
python スクリプト {customerId} {deviceId}

・戻り値
1) 正常時
0
2) エラー時
1

・例
python /opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/quarantine.py DGH1 01234567

