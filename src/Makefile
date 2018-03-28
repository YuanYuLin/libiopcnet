
TARGET = libiopcnet.so

CFLAGS += -I$(SDKSTAGE)/usr/include/libiopcmisc
CFLAGS += -I$(SDKSTAGE)/usr/include/
CFLAGS += -I./include/
CFLAGS += 

LDFLAGS += -L$(SDKSTAGE)/lib/ 
LDFLAGS += -L$(SDKSTAGE)/usr/lib/ 
LDFLAGS += -lc -lpthread -ldl

SRC = 
SRC += ops_net.c

include Makefile.include.lib
