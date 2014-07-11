#ifndef PATTERN_FINDER_H
#define PATTERN_FINDER_H

// gaps need to be same len as bytestr, 0 means find exact, 1 means find
// whatever at that position
void* find_pattern(const unsigned char* bytestr, int len, const bool* gaps);

#endif
