#ifndef PROXY_H
#define PROXY_H

typedef struct {
  char *name1, *email1;
  char *name2, *email2;
  char *tname;
} team_struct;
typedef struct {
    int read_from;
    int fwd_to;
} arg_struct;
#endif
