
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/david/nginx/sbin/nginx -t

	kill -USR2 `cat /home/david/nginx/logs/nginx.pid`
	sleep 1
	test -f /home/david/nginx/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/david/nginx/logs/nginx.pid.oldbin`
