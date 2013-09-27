all: tool

tool: clean
	g++ -g -Wno-deprecated net_utils.h net_utils.c tool.c -o ofp_tool -lpcap -lpthread

clean: 
	rm -rf *~ ofp_tool
