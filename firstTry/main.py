import os
from compiler import Compiler

commpiler = Compiler("./firstTry/yara", "./test.py")
current_directory = os.path.dirname(os.path.abspath(__file__))
test_file_path = os.path.join(current_directory, "test.py")
commpiler.scan_file("./firstTry/test.py")
