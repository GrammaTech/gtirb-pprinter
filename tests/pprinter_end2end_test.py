import unittest
from pathlib import Path
import subprocess
import sys

two_modules_gtirb=Path('tests','two_modules.gtirb')

class TestPrintToStdout(unittest.TestCase):
    def test_print_module0(self): 
        output= subprocess.check_output(['gtirb-pprinter','--ir',str(two_modules_gtirb),'-m','0']).decode(sys.stdout.encoding)
        self.assertTrue('.globl main' in output)
        self.assertFalse('.globl fun' in output)
    
    def test_print_module1(self): 
        output= subprocess.check_output(['gtirb-pprinter','--ir',str(two_modules_gtirb),'-m','1']).decode(sys.stdout.encoding)
        self.assertTrue('.globl fun' in output)
        self.assertFalse('.globl main' in output)
    

class TestPrintToFile(unittest.TestCase):
      def test_print_two_modules(self): 
        subprocess.check_output(['gtirb-pprinter','--ir',str(two_modules_gtirb),'--asm','/tmp/two_modules.s']).decode(sys.stdout.encoding)
        with open('/tmp/two_modules.s','r') as f:
            self.assertTrue('.globl main' in f.read())
        with open('/tmp/two_modules1.s','r') as f:
            self.assertTrue('.globl fun' in f.read())