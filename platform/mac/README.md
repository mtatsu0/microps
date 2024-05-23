# macOSでやった時の変更点メモ
## DAY1
- MakefileのmacOS specific settingsにBASE, CFLAGSを設定。
- platform/macディレクトリを作成。以降platform/linuxに追加するものはplatform/macに追加する。
- macOSにはpthread_barrierがないので、https://github.com/ademakov/DarwinPthreadBarrier を使う。
- macOSにはリアルタイムシグナルがないので、デバイスドライバのハードウェア割り込みにはSIGUSR1を使用し、プロトコル処理のソフトウェア割り込みにはSIGUSR2を使用する。

## DAY2

## DAY3
- driver/ether_tap.hじゃなくてdriver/ether_bpf.hを作成。
- platform/linux/driver/ether_tap.cじゃなくてplatform/mac/driver/ether_bpf.cを作成。
- ETHER_BPF_IRQはSIGUSR1とする（なのでloopbackデバイスと一緒には使えない）
- macOSでbpfデバイスに対してF_SETOWNするとinvalid argumentが出てしまうので、別スレッド作ってbpfデバイスをpollで監視して、そこからETHER_BPF_IRQのシグナルを発生させて無理やり元のコードに繋げる。