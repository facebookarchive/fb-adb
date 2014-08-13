[fb-adb](https://github.com/facebook/fb-adb) is a tool for interacting
with Android systems. It does much of what adb does, but with better
remote shell support and, hopefully, fewer bugs. Differences between
adb and fb-adb are that fb-adb:

  * is binary clean (no LF -> CRLF mangling)
  * transmits and updates window size
  * distinguishes standard output and standard error
  * properly muxes streams with independent flow control
  * allows for ssh-like pty allocation control
  * propagates program exit status instead of always exiting
    with status 0
  * properly escapes program arguments
  * kills remote program
  * provides a generic facility to elevate to root without re-escaping

BUILDING
--------

An out-of-tree build is required.  You'll need a copy of the
[Android NDK](https://developer.android.com/tools/sdk/ndk/index.html):
tell configure about it by setting the `ANDROID_NDK` environment
variable to your NDK path or by using the `--with-android-ndk` argument
to the configure script.

For example:
````
./autogen.sh
export ANDROID_NDK=/path/to/android-ndk
mkdir build
cd build
../configure
make
````

RUNNING
-------

The fb-adb executable itself has no dependencies other than the adb
executable, which must be on `PATH`.  Generally, you can use fb-adb just
like adb; fb-adb forwards unknown commands to adb. fb-adb supports
the same device-selection options that adb does.

`fb-adb shell` is the fancy shell command that supports the features
described above.  Run `fb-adb shell -h` for additional options.
