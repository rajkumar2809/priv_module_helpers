# Helix API連携モジュールのクエリビルダ

FireEyeのSIEM製品である、HelixとのAPI連携でログ検索をする際に必要な検索クエリを作成補助するモジュールです。  

### base.py

ビルダを作成するための基底クラスです。  
個別にimportして利用されることを想定しておらず、各製品向けのビルダ作成時に利用することが想定されています。  

継承した上で、基本的に以下を利用します。  

* フィールドの追加
```python
def add(self, field, value, op=None, is_not=False):
```

* 検索日時に関する指定
```python
def set_from(self, value):
def set_to(self, value):
def set_time_around(self, value, diff=120):
```

* クエリ文字列の取得
```python
def to_query(self):
```

### squid.py

squid(プロキシ製品)向けのビルダです。

### eset.py

ESET(エンドポイント製品)向けのビルダです。
