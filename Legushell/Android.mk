LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

$(info LOCAL_SRC_FILES="$(LOCAL_SRC_FILES)")
$(info BUILD_EXECUTABLE="$(BUILD_EXECUTABLE)")
$(info my-dir="$(my-dir)")
$(info SYSROOT="$(SYSROOT)")
$(info CLEAR_VARS="$(CLEAR_VARS)")
$(info LOCAL_PATH="$(LOCAL_PATH)")
#$(warning "SYSROOT=$(SYSROOT)" )
#$(error "error: this will stop the compile" )


LOCAL_MODULE    := shell
LOCAL_SRC_FILES := shella.cpp

#LOCAL_MODULE    := TestMember
#LOCAL_SRC_FILES := TestMember.cpp

# 隐藏符号
LOCAL_CPPFLAGS += -fvisibility=hidden -O2

# 禁用栈溢出检查
LOCAL_CPPFLAGS += -fno-stack-protector

# 禁用异常扩展
LOCAL_CPPFLAGS += -fno-exceptions


LOCAL_LDLIBS += -llog -lz
LOCAL_LDLIBS += -llog -lz

include $(BUILD_SHARED_LIBRARY)

#LOCAL_FORCE_STATIC_EXECUTABLE := true
#include $(BUILD_EXECUTABLE)

