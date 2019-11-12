CC="/path/to/android-ndk-r20/toolchains/llvm/prebuilt/<platform>/bin/clang"
CFLAGS="--target=aarch64-linux-android24 -fno-addrsig"

build:
	rm -f exploit
	$(CC) $(CFLAGS) getroot.c exploit.c -o exploit

execute: build
	adb shell rm -f /data/local/tmp/exploit
	adb push exploit /data/local/tmp
	adb shell /data/local/tmp/exploit
