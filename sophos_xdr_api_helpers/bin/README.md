各コマンドの説明

[1] デバイス隔離操作
・ファイル
/opt/python_private_modules/priv_module_helpers/sophos_xdr_api_helpers/bin/quarantine.py

・呼出し方
1) 隔離(省略すると隔離実施になる)
python スクリプト {customerId} {deviceId}
python スクリプト {customerId} {deviceId} -quarantine=ON
2) 隔離解除
python スクリプト {customerId} {deviceId} -quarantine=OFF

・戻り値
1) 正常時
0
2) エラー時
1

・例
/opt/python_private_modules/priv_module_helpers/sophos_xdr_api_helpers/bin/quarantine.py DGH1 01234567 -quarantine=OFF

