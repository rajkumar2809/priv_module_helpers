[1] アラート検索
・ファイル
/opt/python_private_modules/priv_module_helpers/splunk_helpers/bin/device_id_cbalerts.py

・呼出し方
1)
python スクリプト {customerId} {deviceId}
2)
python スクリプト {customerId} {deviceId} -timerange=10
3)
python スクリプト {customerId} {deviceId} -timerange=10 -cfg_name=test

Note:
1)
timerangeは、過去何分のアラートを検索するか、という機能です。単位は分で、デフォルトは30分です。
2)
cfg_nameは、モジュール内にあるどのコンフィグを使うかです。想定するのはテスト用の設定利用時のみです。

・戻り値
1) 正常時
[
  {
    "detect_time" : 1572924916",
    "alert_id" : "xxxxxx",
    "severity" : "中",
    "customer_name" : "YSN1",
    "device_id" : "00000000"
  }
]

2) エラー時
1

・例
python /opt/python_private_modules/priv_module_helpers/splunk_helpers/bin/device_id_cbalerts.py DGH1 01234567

