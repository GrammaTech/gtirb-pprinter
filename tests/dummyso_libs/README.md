The files in this directory are used by the dummyso end2end test. The two .s files
are compiled into .so's that the test's rewritten binary should depend on at runtime.
Note, though, they shouldn't be used during rewriting (specifically relinking) time.
