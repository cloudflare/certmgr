build:
	docker build . -f Dockerfile.test -t certmgr:test

test: build
	docker run -it certmgr:test /bin/bash
