#ifndef BYTERUN_UTILS
#define BYTERUN_UTILS

#include "../runtime/runtime.h"

#define todo() failure("unimplemented");

// Evaluates binary operation.
int binop(int op_code, int a, int b);

// Describes stack.
typedef struct {
  int cap;
  int sz;
  int bp[0];
} stack;

// Returns new stack.
stack *stack_new(int cap);

// Push element to the stack.
void push(stack *, int);

// Pops element from the stack and return it.
int pop(stack *);

// Returns top element of the stack.
int top(stack *);

#endif
