# FireEyeHx API連携モジュール

EDR製品:FireEyeHxのAPI連携用モジュールです。  

## 基本的なAPI連携用の各種モジュール  

本フォルダ直下に存在する各スクリプトとなります。  

## コマンドラインツール
### bin,logフォルダ

バージョンに限らず、コマンドベースでAPI連携する場合は、binフォルダ配下の各種スクリプトを実行します。  
また、実行に伴うログ情報がlogフォルダ内に保存されます。

## 設定ファイル
### configフォルダ

コマンドラインによるログ設定や各種API連携に伴うユーザごとの資格情報設定などが保管されています。  

## 本フォルダ直下の各スクリプト
### hx_api_helper.py

以下が利用例となります。
* hostsetの取得
```python
host = "hx09"
customer = "DGH2"
res = get_hostset(customer, host, with_case=True, with_multi=with_multi)
print res
```

* enterprisesearchでの検索追加
```python
values = [
    "https://yahoo.co.jp",
    "https://test.co.jp",
    "https://google.com"
]
queries = make_queries_by_url(values)
res = set_new_enterprise_search("DGH2", queries)
print res
```

* enterprisesearchでの検索結果の取得・削除
```python
_id = 25
customer = "DGH2"
# 結果取得
res = get_result_enterprise_search(customer, _id)
print json.dumps(res, indent=4)

# 結果取得
flag = delete_enterprise_search(customer, _id)
print flag
```
