# macOSでやった時の変更点メモ
## DAY1
- MakefileのmacOS specific settingsにBASE, CFLAGSを設定。
- platform/macディレクトリを作成。以降platform/linuxに追加するものはplatform/macに追加する。
- mac0Sにはpthread_barrierがないので、https://github.com/ademakov/DarwinPthreadBarrier を使う。
- macOSにはリアルタイムシグナルがないので、デバイスドライバのハードウェア割り込みにはSIGUSR1を使用し、プロトコル処理のソフトウェア割り込みにはSIGUSR2を使用する。

## DAY2