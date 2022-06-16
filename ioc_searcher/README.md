# IOC情報の包括取得用モジュール

DH-SOCのSplunkに保管しているIOC情報のマッチング用機能です。  
DH-SOCはIOC情報のソースとして、以下があるのでそれぞれサーチをかける挙動となります。  
- cyfirma
- 独自

## 基本的なAPI連携用の各種モジュール  
### 本フォルダ直下のファイル

### main.py

Splunk内のIOC情報を検索する機能を提供します。  
同プロセス内で、検索したことのあるIOC情報をキャッシュします。  

* 引数にマッチした全てのIOC情報を取り込む機能
```python
def cache_all_iocs(hashlist=None, addrlist=None, hostlist=None, limit=100):
```

* IOC情報を取得するクラス
```python
class IocChecker(object):
  def __init__(self, ioc_src="all"):
    # ..... 初期化。基本はallで利用だが、ioc_parserフォルダ内の個別IOCソースを指定できる
  def check_domains(self, values):
    # .....引数に渡されたドメイン情報(list<str>)にマッチしたものをreturnします。
  def check_ipv4(self, values):
    # .....引数に渡されたIP情報(list<str>)にマッチしたものをreturnします。
  def check_hashes(self, values):
    # .....引数に渡されたハッシュ情報(list<str>)にマッチしたものをreturnします。
```

### helper.py

binのコマンドを実行することを補助するhelperメソッド。

## 設定ファイル
### configフォルダ

利用しない想定です。今後削除予定です。

## コマンドラインツール
### bin,logフォルダ

バージョンに限らず、コマンドベースでAPI連携する場合は、binフォルダ配下の各種スクリプトを実行します。  
また、実行に伴うログ情報がlogフォルダ内に保存されます。

## IOCソース毎のparser
### ioc_parserフォルダ

IOCソース毎に個別のクラスを作成しています。  
Splunkのサーチやその結果のパーサーとして利用を想定しています。

## IOCソース毎のparser
### ioc_parserフォルダ

IOCソース毎に個別のクラスを作成しています。  
Splunkのサーチやその結果のパーサーとして利用を想定しています。

## 製品毎でのIOC検索機能
### productsフォルダ

各製品で取得したIOCで検索する機能です。  
bin/commands.pyからの利用をしております。  
各製品のAPI連携用モジュールも利用しています。
