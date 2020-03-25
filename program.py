from test import *

suite = unittest.TestLoader().loadTestsFromTestCase(TestForwardingTable)
unittest.TextTestRunner(verbosity = 2).run(suite)