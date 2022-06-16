# 各コマンドの説明

### [1] 隔離メッセージ送信
・ファイル
/opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/send_msg.py

・呼出し方
1)
python スクリプト {customerId} {deviceId}
2)
python スクリプト {customerId} {deviceId} -script={scriptName}
※messageの内容は、scriptで指定したスクリプト内で別途管理することになる。基本は以下。
　本端末はマルウェアに感染した恐れのあるため、ネットワークから隔離されます。
スクリプト名が指定されていない場合は、SEND_CONTAINMENT_MSGを実行する。

・戻り値
1) 正常時
0
2) エラー時
1

・例
python /opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/send_msg.py DGH1 01234567
python /opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/send_msg.py DGH1 01234567 -script=SEND_RELEASE_MSG

### [2] デバイス隔離実施
・ファイル
/opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/quarantine.py

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
python /opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/quarantine.py DGH1 01234567

### [3] ホワイトリスト・ブラックリスト登録
・ファイル
/opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/reputation_sha256.py

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
{"meta": {"query_time": 0.011553447, "pagination": {"total": 1, "limit": 100, "after": "WzE2MzAyMTQzMzY2NDEsIjliODk5OWMwYzM2ZGQwMDc0Nzk2NzBmY2QwNGZmNDk0NWE4YjhiZGI5MzBlZGI1NGQwMzU1NDQ1MGQwMDEwNDMiXQ==", "offset": 1}, "powered_by": "ioc-manager", "trace_id": "29775a0c-651e-49d3-8788-be5c48931a51"}, "errors": null, "resources": [{"from_parent": false, "modified_by": "732a9ad755fa4c10815fe8b0c512e850", "severity": "", "applied_globally": true, "platforms": ["windows", "mac", "linux"], "deleted": false, "expired": false, "tags": ["WHITE_LIST"], "value": "af62e6b3d475879c4234fe7bd8ba67ff6544ce6510131a069aaac75aa92aee7a", "source": "mdr_service", "created_on": "2021-08-29T05:18:56.641401326Z", "modified_on":"2021-08-29T05:18:56.641401326Z", "created_by": "732a9ad755fa4c10815fe8b0c512e850", "action": "allow", "metadata": {"av_hits": -1, "signed": false, "filename": "foo.exe"}, "type": "sha256", "id": "9b8999c0c36dd007479670fcd04ff4945a8b8bdb930edb54d03554450d001043", "description": "MDR Service 2021/08/29"}]}
2) 登録なし
{"meta": {"query_time": 0.013412006, "pagination": {"total": 0, "limit": 100, "offset": 0}, "powered_by": "ioc-manager", "trace_id": "81a05b74-0147-479b-8b2a-b36fe3298b5b"}, "errors": null, "resources": []}

・例
1)ブラックリスト登録
python /opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/reputation_sha256.py DGH1 add c55c4a6df95012882bd7984fd027241b50f281cae0fa49183d91126fbe445f35 -filename "test.exe" -list_type BLACK_LIST
2)ホワイトリスト登録
python /opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/reputation_sha256.py DGH1 add c55c4a6df95012882bd7984fd027241b50f281cae0fa49183d91126fbe445f35 -filename "test.exe" -list_type WHITE_LIST
3)登録削除
python /opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/reputation_sha256.py DGH1 delete c55c4a6df95012882bd7984fd027241b50f281cae0fa49183d91126fbe445f35
4)登録確認
python /opt/python_private_modules/priv_module_helpers/csapi_helpers/bin/reputation_sha256.py DGH1 search c55c4a6df95012882bd7984fd027241b50f281cae0fa49183d91126fbe445f35
