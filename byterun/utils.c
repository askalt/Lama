#include "utils.h"

extern size_t __gc_stack_top, __gc_stack_bottom;

stack *stack_new(int cap) {
  stack *ret = malloc(sizeof(stack) + sizeof(int) * cap);
  if (ret == NULL)
    failure("unable to allocate memory for stack ");
  ret->sz = 0;
  ret->cap = cap;
  __gc_stack_bottom = __gc_stack_top = (size_t)ret->bp;
  return ret;
}

void push(stack *st, int e) {
  if (st->sz == st->cap) {
    failure("stack is full ");
  }
  st->bp[st->sz++] = e;
  __gc_stack_top += sizeof(int);
}

int pop(stack *st) {
  if (st->sz == 0) {
    failure("stack is empty ");
  }
  int ret = st->bp[--st->sz];
  __gc_stack_top -= sizeof(int);
  return ret;
}

int top(stack *st) {
  if (st->sz == 0) {
    failure("stack is empty ");
  }
  return st->bp[st->sz - 1];
}
