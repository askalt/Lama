TESTS=$(sort $(basename $(wildcard generated*.lama)))

LAMAC = ../../src/lamac
BYTERUN = ../../byterun/byterun

.PHONY: check $(TESTS)

check: $(TESTS)

$(TESTS): %: %.lama
	@echo $@
	@LAMA=../../runtime $(LAMAC) $< && cat $@.input | ./$@ > $@.log && diff $@.log orig/$@.log
	@cat $@.input | $(LAMAC) -i $< > $@.log && diff $@.log orig/$@.log
	@cat $@.input | $(LAMAC) -s $< > $@.log && diff $@.log orig/$@.log
	@LAMA=../../runtime $(LAMAC) -b $@.lama
	@cat $@.input | $(BYTERUN) -i $@.bc > $@.log && diff $@.log orig/$@.log

clean:
	rm -f *.log *.s *~
	find . -maxdepth 1 -type f -not -name '*.*' -not -name 'Makefile' -delete
