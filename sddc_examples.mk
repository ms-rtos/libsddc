#*********************************************************************************************************
#
#                                 ����������Ϣ�������޹�˾
#
#                                   ΢�Ͱ�ȫʵʱ����ϵͳ
#
#                                       MS-RTOS(TM)
#
#                               Copyright All Rights Reserved
#
#--------------�ļ���Ϣ--------------------------------------------------------------------------------
#
# ��   ��   ��: sddc_examples.mk
#
# ��   ��   ��: IoT Studio
#
# �ļ���������: 2016 �� 10 �� 08 ��
#
# ��        ��: ���ļ��� IoT Studio ���ɣ��������� Makefile ���ܣ������ֶ��޸�
#*********************************************************************************************************

#*********************************************************************************************************
# Clear setting
#*********************************************************************************************************
include $(CLEAR_VARS_MK)

#*********************************************************************************************************
# Target
#*********************************************************************************************************
LOCAL_TARGET_NAME := sddc_examples

#*********************************************************************************************************
# Source list
#*********************************************************************************************************
LOCAL_SRCS := \
./src/example/message/sddc_message_example.c \
./src/example/connector/sddc_connector_example.c \
./src/example/demo/sddc_demo.c

#*********************************************************************************************************
# Header file search path (eg. LOCAL_INC_PATH := -I"Your hearder files search path")
#*********************************************************************************************************
LOCAL_INC_PATH := \
-I"$(MSRTOS_BASE_PATH)/libsddc/src" \
-I"$(MSRTOS_BASE_PATH)/cjson/src/cJSON"

#*********************************************************************************************************
# Pre-defined macro (eg. -DYOUR_MARCO=1)
#*********************************************************************************************************
LOCAL_DSYMBOL := 

#*********************************************************************************************************
# Depend library (eg. LOCAL_DEPEND_LIB := -la LOCAL_DEPEND_LIB_PATH := -L"Your library search path")
#*********************************************************************************************************
LOCAL_DEPEND_LIB      := -lsddc -lcjson -lmbedtls -lmbedx509 -lmbedcrypto 
LOCAL_DEPEND_LIB_PATH := \
-L"$(MSRTOS_BASE_PATH)/libsddc/$(OUTDIR)" \
-L"$(MSRTOS_BASE_PATH)/cJSON/$(OUTDIR)" \
-L"$(MSRTOS_BASE_PATH)/mbedtls/$(OUTDIR)"

#*********************************************************************************************************
# C++ config
#*********************************************************************************************************
LOCAL_USE_CXX        := no
LOCAL_USE_CXX_EXCEPT := no

#*********************************************************************************************************
# Code coverage config
#*********************************************************************************************************
LOCAL_USE_GCOV := no

#*********************************************************************************************************
# Depend target
#*********************************************************************************************************
LOCAL_DEPEND_TARGET := $(OUTDIR)/libsddc.a

include $(UNIT_TEST_MK)

#*********************************************************************************************************
# End
#*********************************************************************************************************