.PHONY: all, local, server, clean

all: local server

local:
	sh script/build.sh local

server:
	sh script/build.sh server

clean:
	rm -rf hk-local hk-server