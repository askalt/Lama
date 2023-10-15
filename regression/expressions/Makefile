TESTS=$(sort $(basename $(wildcard generated*.lama)))

RC = ../../src/lamac
BYTERUN = ../../byterun/byterun

.PHONY: check $(TESTS)

check: $(TESTS)

$(TESTS): %: %.lama
	@echo $@
	@LAMA=../../runtime $(RC) $< && cat $@.input | ./$@ > $@.log && diff $@.log orig/$@.log
	@cat $@.input | $(RC) -i $< > $@.log && diff $@.log orig/$@.log
	@cat $@.input | $(RC) -s $< > $@.log && diff $@.log orig/$@.log
	@LAMA=../../runtime $(RC) -b $@.lama
	@cat $@.input | $(BYTERUN) -i $@.bc > $@.log && diff $@.log orig/$@.log

clean:
	rm -f *.log *.s *~
	find . -maxdepth 1 -type f -not -name '*.*' -not -name 'Makefile' -delete

