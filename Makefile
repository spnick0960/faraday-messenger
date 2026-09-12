.PHONY: test relay sim

test:
	$(MAKE) -C server test

relay:
	$(MAKE) -C server relay

sim:
	$(MAKE) -C server sim
