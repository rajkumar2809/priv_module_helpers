# cyfirma API連携モジュール

脅威インテリジェンスサービス:cyfirmaとAPI連携してIOC情報を取得する機能を提供するモジュールです。  

## 基本的なAPI連携用の各種モジュール  
### 本フォルダ直下のファイル

### main.py

IOC情報を取得する機能を提供します。  
基本的には以下の関数が呼び出されることを想定しています。  
多くの場合、差分取得を想定していますので、by_dffをTrueにします。(default)
```python
def get_ioc_by_json(by_raw=False, by_diff=True, by_all=True):
#  by_rawがFalseである場合は、rawdata["indicators"]["indicators"]の内容を応答
```

重要なこととして、差分取得はAPIでコールする毎に差分を受けてるものになるため、Splunkからの定期実行以外ではアクセスしてはいけないものとなる。  
(その際にCLI等で取得した情報はSplunkでは取り込まれなくなるため)

## 設定ファイル
### configフォルダ

APIキー情報が格納されています。
