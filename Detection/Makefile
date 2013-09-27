all: detect

detect: clean
	g++ -g -Wno-deprecated net_utils.h net_utils.c detect.c -o ofp_detect -lpcap -lpthread

clean: 
	rm -rf *~ ofp_detect
