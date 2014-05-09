s/^([A-Z0-9_]+) (iflag|oflag|lflag|c_cc)$/#ifdef \2\
\U\2\E(\1)\
#endif/
