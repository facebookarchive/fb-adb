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

DOWNLOADS
---------
You can use [Homebrew](http://brew.sh/) to install fb-adb binaries:

````
brew install fb-adb
````

BUILDING
--------

An out-of-tree build is required.  You'll need a copy of the
[Android NDK](https://developer.android.com/tools/sdk/ndk/index.html):
tell configure about it by setting the `ANDROID_NDK` environment
variable to your NDK path or by using the `--with-android-ndk` argument
to the configure script.  You'll also need to tell configure where the
Android SDK is by setting the `ANDROID_SDK` environment variable or
using the `--with-android-sdk` argument.

For example:
````
./autogen.sh
export ANDROID_NDK=/path/to/android-ndk
export ANDROID_SDK=/path/to/android-sdk
mkdir build
cd build
../configure
make
````

If building on Mac, you need `gmake` to build. You can use
[Homebrew](http://brew.sh/) to get it:
```
brew install homebrew/core/make
```
on earlier systems this was:
```
brew tap homebrew/dupes
brew install homebrew/dupes/make
```
and then use `gmake` instead of `make`.


RUNNING
-------

The fb-adb executable itself has no dependencies other than the adb
executable, which must be on `PATH`.  Generally, you can use fb-adb just
like adb; fb-adb forwards unknown commands to adb. fb-adb supports
the same device-selection options that adb does.

`fb-adb shell` is the fancy shell command that supports the features
described above.  Run `fb-adb shell -h` for additional options.

EXAMPLES
--------

* Capture a screenshot from device and write it locally to a timestamped file:

    `fb-adb rcmd screencap -p > screenshot-$(timestamp).png`

* Dump `database.db` of the `com.bar.foo` app:

    `fb-adb rcmd -u com.bar.foo sqlite3 /data/data/com.bar.foo/databases/database.db .d`

* Open remote shell as the user `com.bar.foo`:

    `fb-adb shell -u com.bar.foo`
