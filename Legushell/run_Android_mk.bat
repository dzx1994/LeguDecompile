REM @ECHO OFF

SET __NDK_ROOT=%AD_NDK%
SET BuildTool=%__NDK_ROOT%\build\ndk-build
REM SET __APP_ABI=armeabi-v7a
REM SET __APP_PLATFORM=android-19
REM SET __APP_STL=c++_static
SET __SYSROOT=%__NDK_ROOT%\sysroot

CALL %BuildTool%  -B  APP_BUILD_SCRIPT=./Android.mk  NDK_APPLICATION_MK=./Application.mk  SYSROOT=%__SYSROOT%  NDK_ROOT=%__NDK_ROOT%  NDK_PROJECT_PATH=.
PAUSE
