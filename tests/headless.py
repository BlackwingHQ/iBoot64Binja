from binaryninja import BinaryViewType
import sys, os

if len(sys.argv) != 2:
    print("A path or file name is required")
    sys.exit(1)
if os.path.isdir(sys.argv[1]):
    files = os.listdir(sys.argv[1])
    for file in files:
        print(f"Loading {sys.argv[1]}")
        bv = BinaryViewType.get_view_of_file(file)
elif os.path.isfile(sys.argv[1]):
    bv = BinaryViewType.get_view_of_file(sys.argv[1])
