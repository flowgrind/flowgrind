if USE_DOXYGEN

CLEANFILES = doxyfile.stamp

.PHONY: html.timestamp

html: html.timestamp

html.timestamp:
	$(DOXYGEN) Doxyfile
	touch $@

clean-local:
	rm -rf html latex html.timestamp

endif
