CXX = g++
#FFMPEG = /usr/local
#INCLUDE_PATH = $(FFMPEG)/include/
#INCLUDE += 
#LIB_PATH = $(FFMPEG)/lib/
#CFLAGS = -I$(FFMPEG)/include -L$(FFMPEG)/lib
#CFLAGS = -I/include 
#CXXFLAGS = -ldl -lpthread  -lz -lm
#CXXFLAGS = -lcrypto 
TARGET = crypt_java 
DIRS = .
OBJS_FILES = $(foreach dir, $(DIRS), $(wildcard $(dir)/*.cpp))
OBJS = $(patsubst %.cpp, %.o, $(OBJS_FILES))
RM = rm -f

#LKFLAGS =
#INSTALLDIR = /mnt/
#install:
#CP = cp
#$(CP) $(TARGET) $(INSTALLDIR)
#VPATH = path1:path2...
#$(wildcard *.c) #搜索当前目前下匹配*.c的所有文件并返回文件列表
#$(patsubst %.c, %.o, $(wildcard *.c)) #将搜索到的与*.c匹配的所有以.c后缀的文件替换成以.o后缀的文件
#$(foreach dir, $(DIRS), $(wildcard $(dir)/*.c)) #循环$(DIRS)中的目录(以空格分隔)依次赋给变量dir，然后搜索该目录下匹配*.c的所有文件并返回文件列表

all:$(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $^ -o $@ #$(CXXFLAGS)

$(OBJS): %.o:%.cpp
	$(CXX) -g -c $< -o $@ #$(CFLAGS)

#test.o: test.cpp
#	$(CXX) $(CFLAGS) $^

clean:
	@echo "cleaning project"
	-$(RM) $(OBJS)
	@echo "clean completed"
.PHONY: clean
