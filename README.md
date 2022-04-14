# Google App Engine(GAE) 用 Vue+Flask テンプレート

以下で動作するシンプルなテンプレートです。

    デプロイ先：Google App Engine(GAE) 
    フロントエンド：Vue.js v3 (vue cliを使用。vue routerを入れてます。)
    バックエンド：Flask 2.1.1 python 3.8　<- 本リポジトリ

フロントエンド側のリポジトリは以下です。
https://github.com/0gravity000/template-vue

## 環境を構築する

1.このリポジトリをローカルPCの任意の場所にクローンする。

    git clone https://github.com/0gravity000/template-vue-flask.git

2.クローンした場所へ移動し、python仮想環境を作成する。
例) venvというフォルダ名で仮想環境を作成

    python -m venv venv

3.フロントエンド側で vue/cli をインストールする。

    npm install -g @vue/cli

4.フロントエンド側のリポジトリをローカルPCの任意の場所にクローンする。

    git clone https://github.com/0gravity000/template-vue

5.クローンした場所へ移動し、以下のコマンドを実行する。

    npm install

6.開発環境（production) ビルドする。

    npm run build

7.手順6.で生成された dist フォルダをバックエンドリポジトリの「vuejs」フォルダ内にコピーする

    \template-vue-flask
    ├─venv
    └─vuejs <-- フォルダを作成する
        └─dist  <-- ここにコピーする
            └─static
                ├─css
                ├─img
                └─js

8.バックエンド側の \template-vue-flask フォルダに移動し、仮想環境を Activate する。

9.ローカルサーバーを起動し、正常に表示されることを確認する。

    python3 main.py


## Google App Engine(GAE) にデプロイ(deploy)する

バックエンド側の \template-vue-flask フォルダに移動し、Google App Engine(GAE) にデプロイ(deploy)する

gcloud CLI を初期化

    gcloud init

App Engine アプリを作成

    gcloud app create

デプロイ(deploy)する

    gcloud app deploy

アプリを表示する

    gcloud app browse

参考サイト： [App Engine スタンダード環境での Python 3 のクイックスタート](https://cloud.google.com/appengine/docs/standard/python3/create-app?hl=ja)
