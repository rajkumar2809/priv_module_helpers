# 各コマンドの説明

全て、現在はv6APIを想定しています。

### [1] デバイス検索
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

### [2] 隔離メッセージ送信
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

### [3] デバイス隔離実施
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

### [4] ホワイトリスト・ブラックリスト登録
・ファイル
/opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/reputation_sha256.py

・呼出し方
1)
python スクリプト {customerId} add {sha256} -filename {filename} -list_type {BLAC_LIST or WHITE_LIST}
2)
python スクリプト {customerId} delete {sha256}
3)
python スクリプト {customerId} search {sha256}

・戻り値
1.登録及び削除時

1) 正常時
0
2) エラー時
1

2.sha256での登録の検索
1) 登録あり
jsonデータが応答。以下は応答データのサンプル。
{"num_found": 1, "results": [{"sha256_hash": "sha256のハッシュ情報", "description": "MDR Service yyyy/mm/dd", "created_by": "作成者", "filename": "ファイル名", "source": "APP", "create_time": "yyyy-mm-ddThh:mm:ss.000", "override_type": "SHA256", "id": "登録された情報のID", "override_list": "BLACK_LISTまたはWHITE_LIST", "source_ref": null}]}
2) 登録なし
{"num_found": 0, "results": []}

・例
1)ブラックリスト登録
python /opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/reputation_sha256.py DGH1 add c55c4a6df95012882bd7984fd027241b50f281cae0fa49183d91126fbe445f35 -filename "test.exe" -list_type BLACK_LIST
2)ホワイトリスト登録
python /opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/reputation_sha256.py DGH1 add c55c4a6df95012882bd7984fd027241b50f281cae0fa49183d91126fbe445f35 -filename "test.exe" -list_type WHITE_LIST
3)登録削除
python /opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/reputation_sha256.py DGH1 delete c55c4a6df95012882bd7984fd027241b50f281cae0fa49183d91126fbe445f35
4)登録確認
python /opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/reputation_sha256.py DGH1 search c55c4a6df95012882bd7984fd027241b50f281cae0fa49183d91126fbe445f35

### [5] イベント検索
・ファイル
1) ハッシュによる簡易検索
/opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/search_ioc.py
2) カスタムクエリによる検索
/opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/search_ioc2.py


1) SHA256ハッシュによる検索

両方とも利用可能。
- search_ioc.py
・例
python /opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/search_ioc.py {customerId} {sha256hash}

- search_ioc2.py
・例1: ハッシュでとりあえず検索
/opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/search_ioc2.py {customerId} "process_hash={sha256hash}"

・例2: 親プロセスハッシュで検索
/opt/python_private_modules/priv_module_helpers/cbapi_helpers/bin/search_ioc2.py {customerId} "parent_hash={sha256hash}"

2) ハッシュ以外の条件で検索

search_ioc2.pyを利用して可能。検索方法はCarbonBlack上での検索と同様。
