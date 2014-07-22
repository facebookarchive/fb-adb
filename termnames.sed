# Copyright 2004-present Facebook. All Rights Reserved.
s/^([A-Z0-9_]+) (IFLAG|OFLAG|LFLAG|C_CC)$/#ifdef \1\
\2(\1)\
#endif/
