s/^([A-Z0-9_]+) (iflag|oflag|lflag|c_cc)$/#ifdef \1\
\U\2\E(\1)\
#endif/
