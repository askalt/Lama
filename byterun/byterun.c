/* Lama SM Bytecode interpreter */

//#define DEBUG_PRINT 1

#ifdef DEBUG_PRINT
#define debug(...) printf(__VA_ARGS__)
#else
#define debug(...) 42
#endif

#include "../runtime/runtime.h"
#include "utils.h"

#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>

typedef struct {
  int tag;
  char contents[0];
} data;

// Lama runtime defines.
#define UNBOXED(x) (((int)(x)) & 0x0001)
#define UNBOX(x) (((int)(x)) >> 1)
#define BOX(x) ((((int)(x)) << 1) | 0x0001)
#define TO_DATA(x) ((data *)((char *)(x) - sizeof(int)))
#define LEN(x) ((x & 0xFFFFFFF8) >> 3)

// Decode defines.
#define INT (ip += sizeof(int), *(int *)(ip - sizeof(int)))
#define BYTE *ip++
#define STRING get_string(bf, INT)
#define FAIL failure("ERROR: invalid opcode %d-%d\n", h, l)

static char *ops[] = {
    "+", "-", "*", "/", "%", "<", "<=", ">", ">=", "==", "!=", "&&", "!!"};
static char *pats[] = {"=str", "#string", "#array", "#sexp",
                       "#ref", "#val",    "#fun"};
static char *lds[] = {"LD", "LDA", "ST"};

void *__start_custom_data;
void *__stop_custom_data;

/* The unpacked representation of bytecode file */
typedef struct {
  char *string_ptr;              /* A pointer to the beginning of the string table */
  int  *public_ptr;              /* A pointer to the beginning of publics table    */
  char *code_ptr;                /* A pointer to the bytecode itself               */
  int  *global_ptr;              /* A pointer to the global area                   */
  int   stringtab_size;          /* The size (in bytes) of the string table        */
  int   global_area_size;        /* The size (in words) of global area             */
  int   public_symbols_number;   /* The number of public symbols                   */
  char  buffer[0];               
} bytefile;

/* Gets a string from a string table by an index */
char* get_string (bytefile *f, int pos) {
  return &f->string_ptr[pos];
}

/* Gets a name for a public symbol */
char* get_public_name (bytefile *f, int i) {
  return get_string (f, f->public_ptr[i*2]);
}

/* Gets an offset for a publie symbol */
int get_public_offset (bytefile *f, int i) {
  return f->public_ptr[i*2+1];
}

/* Reads a binary bytecode file by name and unpacks it */
bytefile* read_file (char *fname) {
  FILE *f = fopen (fname, "rb");
  long size;
  bytefile *file;

  if (f == 0) {
    failure ("%s\n", strerror (errno));
  }
  
  if (fseek (f, 0, SEEK_END) == -1) {
    failure ("%s\n", strerror (errno));
  }

  file = (bytefile*) malloc (sizeof(int)*4 + (size = ftell (f)));

  if (file == 0) {
    failure ("*** FAILURE: unable to allocate memory.\n");
  }
  
  rewind (f);

  if (size != fread (&file->stringtab_size, 1, size, f)) {
    failure ("%s\n", strerror (errno));
  }
  
  fclose (f);
  
  file->string_ptr  = &file->buffer [file->public_symbols_number * 2 * sizeof(int)];
  file->public_ptr  = (int*) file->buffer;
  file->code_ptr    = &file->string_ptr [file->stringtab_size];
  file->global_ptr  = (int*) malloc (file->global_area_size * sizeof (int));
  
  return file;
}

/* Disassembles the bytecode pool */
void disassemble (FILE *f, bytefile *bf) {  
  char *ip     = bf->code_ptr;
  do {
    char x = BYTE,
         h = (x & 0xF0) >> 4,
         l = x & 0x0F;

    fprintf (f, "0x%.8x:\t", ip-bf->code_ptr-1);
    
    switch (h) {
    case 15:
      goto stop;
      
    /* BINOP */
    case 0:
      fprintf (f, "BINOP\t%s", ops[l-1]);
      break;
      
    case 1:
      switch (l) {
      case  0:
        fprintf (f, "CONST\t%d", INT);
        break;
        
      case  1:
        fprintf (f, "STRING\t%s", STRING);
        break;
          
      case  2:
        fprintf (f, "SEXP\t%s ", STRING);
        fprintf (f, "%d", INT);
        break;
        
      case  3:
        fprintf (f, "STI");
        break;
        
      case  4:
        fprintf (f, "STA");
        break;
        
      case  5:
        fprintf (f, "JMP\t0x%.8x", INT);
        break;
        
      case  6:
        fprintf (f, "END");
        break;
        
      case  7:
        fprintf (f, "RET");
        break;
        
      case  8:
        fprintf (f, "DROP");
        break;
        
      case  9:
        fprintf (f, "DUP");
        break;
        
      case 10:
        fprintf (f, "SWAP");
        break;

      case 11:
        fprintf (f, "ELEM");
        break;
        
      default:
        FAIL;
      }
      break;
      
    case 2:
    case 3:
    case 4:
      fprintf (f, "%s\t", lds[h-2]);
      switch (l) {
      case 0: fprintf (f, "G(%d)", INT); break;
      case 1: fprintf (f, "L(%d)", INT); break;
      case 2: fprintf (f, "A(%d)", INT); break;
      case 3: fprintf (f, "C(%d)", INT); break;
      default: FAIL;
      }
      break;
      
    case 5:
      switch (l) {
      case  0:
        fprintf (f, "CJMPz\t0x%.8x", INT);
        break;
        
      case  1:
        fprintf (f, "CJMPnz\t0x%.8x", INT);
        break;
        
      case  2:
        fprintf (f, "BEGIN\t%d ", INT);
        fprintf (f, "%d", INT);
        break;
        
      case  3:
        fprintf (f, "CBEGIN\t%d ", INT);
        fprintf (f, "%d", INT);
        break;
        
      case  4:
        fprintf (f, "CLOSURE\t0x%.8x", INT);
        {int n = INT;
         for (int i = 0; i<n; i++) {
         switch (BYTE) {
           case 0: fprintf (f, "G(%d)", INT); break;
           case 1: fprintf (f, "L(%d)", INT); break;
           case 2: fprintf (f, "A(%d)", INT); break;
           case 3: fprintf (f, "C(%d)", INT); break;
           default: FAIL;
         }
         }
        };
        break;
          
      case  5:
        fprintf (f, "CALLC\t%d", INT);
        break;
        
      case  6:
        fprintf (f, "CALL\t0x%.8x ", INT);
        fprintf (f, "%d", INT);
        break;
        
      case  7:
        fprintf (f, "TAG\t%s ", STRING);
        fprintf (f, "%d", INT);
        break;
        
      case  8:
        fprintf (f, "ARRAY\t%d", INT);
        break;
        
      case  9:
        fprintf (f, "FAIL\t%d", INT);
        fprintf (f, "%d", INT);
        break;
        
      case 10:
        fprintf (f, "LINE\t%d", INT);
        break;

      default:
        FAIL;
      }
      break;
      
    case 6:
      fprintf (f, "PATT\t%s", pats[l]);
      break;

    case 7: {
      switch (l) {
      case 0:
        fprintf (f, "CALL\tLread");
        break;
        
      case 1:
        fprintf (f, "CALL\tLwrite");
        break;

      case 2:
        fprintf (f, "CALL\tLlength");
        break;

      case 3:
        fprintf (f, "CALL\tLstring");
        break;

      case 4:
        fprintf (f, "CALL\tBarray\t%d", INT);
        break;

      default:
        FAIL;
      }
    }
    break;
      
    default:
      FAIL;
    }

    fprintf (f, "\n");
  }
  while (1);
 stop: fprintf (f, "<end>\n");
}

/* Dumps the contents of the file */
void dump_file (FILE *f, bytefile *bf) {
  int i;
  
  fprintf (f, "String table size       : %d\n", bf->stringtab_size);
  fprintf (f, "Global area size        : %d\n", bf->global_area_size);
  fprintf (f, "Number of public symbols: %d\n", bf->public_symbols_number);
  fprintf (f, "Public symbols          :\n");

  for (i=0; i < bf->public_symbols_number; i++) 
    fprintf (f, "   0x%.8x: %s\n", get_public_offset (bf, i), get_public_name (bf, i));

  fprintf (f, "Code:\n");
  disassemble (f, bf);
}

static char *chars =
    "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

int char_index(char c) {
  int l = strlen(chars);
  for (int i = 0; i < l; ++i) {
    if (chars[i] == c) {
      return i;
    }
  }
  failure("unexpected char ");
}

int hash(char *s) {
  int l = strlen(s);
  if (l > 4)
    l = 4;
  int h = 0;
  for (int i = 0; i < l; ++i) {
    h = (h << 6) | char_index(s[i]);
  }
  return h;
}

int binop(int op_code, int a, int b) {
  switch (op_code) {
  case 0:
    return a + b;
  case 1:
    return a - b;
  case 2:
    return a * b;
  case 3:
    return a / b;
  case 4:
    return a % b;
  case 5:
    return a < b;
  case 6:
    return a <= b;
  case 7:
    return a > b;
  case 8:
    return a >= b;
  case 9:
    return a == b;
  case 10:
    return a != b;
  case 11:
    return a && b;
  case 12:
    return a || b;
  default:
    failure("unexpected operation code: %d ", op_code);
  }
}

// Operands stack size.
const int OP_STACK_SIZE = 100000;

// Helper buffer size.
const int BUFF_SIZE = 2048;

int call_Bsexp(int n, int hash, int *args);
int call_Barray(int n, int *args);
int call_Bclosure(int n, int addr, int *args);

typedef struct {
  int *ebp;
  int nArgs;
  int nLocal;
  int ret_offset;
  int is_closure;
  struct Frame *prev;
} Frame;

Frame *frame_new(int *ebp, int nArgs, int nLocal, int ret_offset,
                 int is_closure, Frame *prev) {
  Frame *ret = malloc(sizeof(Frame));
  ret->ebp = ebp;
  ret->nArgs = nArgs;
  ret->nLocal = nLocal;
  ret->ret_offset = ret_offset;
  ret->is_closure = is_closure;
  ret->prev = prev;
  return ret;
}

int *lda(Frame *frame, stack *op_stack, int typ, int index) {
  debug("\nlda(%d, %d)\n", typ, index);
  switch (typ) {
  case 0:
    // Global variable. Take from the stack beginning.
    return &op_stack->bp[index];
  case 1:
    // Local variable. It located immediately after ebp.
    return &frame->ebp[index];
  case 2:
    // Argument. It located immediately before ebp.
    return frame->ebp - (index + 1);
  case 3: {
    // Captured.
    // Closure located before args.
    int closure = *(frame->ebp - (frame->nArgs + 1));
    int *captured = ((int *)closure) + 1;
    return &captured[index];
  }
  default:
    failure("unexpected typ ");
  }
}

/* Interprets file bytecode */
void interpret(bytefile *bf, char *filename) {
  // Init Lama runtime.
  __init();

  char *ip = bf->code_ptr;
  int *buf = malloc(sizeof(int) * BUFF_SIZE);
  stack *op_stack = stack_new(OP_STACK_SIZE);

  int global_cnt = bf->global_area_size;

  // Reserve place for global variables.
  for (int i = 0; i < global_cnt; ++i) {
    push(op_stack, 0);
  }

  Frame *current = frame_new(&op_stack->bp[op_stack->sz], 0, 0, 0, 0, NULL);

  for (;;) {
    char x = BYTE;
    char h = (x & 0xF0) >> 4;
    char l = x & (0x0F);
    debug("0x%.8x:\n", ip - bf->code_ptr - 1);

#ifdef DEBUG_PRINT
    debug("op stack info:\n");
    debug("size = %d\n", op_stack->sz);
    debug("elems = [");
    for (int i = 0; i < op_stack->sz; ++i) {
      if (i)
        debug(", ");
      debug("%d", op_stack->bp[i]);
    }
    debug("]\n");
#endif

    switch (h) {
    case 0: {
      debug("BINOP\t%s", ops[l - 1]);
      int b = pop(op_stack);
      int a = pop(op_stack);
      push(op_stack, BOX(binop(l - 1, UNBOX(a), UNBOX(b))));
      break;
    }

    case 1: {
      switch (l) {
      case 0: {
        int val = INT;
        debug("CONST\t%d", val);
        push(op_stack, BOX(val));
        break;
      }
      case 1: {
        char *str = STRING;
        debug("STRING\t%s", str);
        push(op_stack, Bstring(str));
        break;
      }
      case 2: {
        char *name = STRING;
        int h = hash(name);
        int nArgs = INT;
        debug("SEXP\t%s %d", name, nArgs);
        int Bsexp = call_Bsexp(nArgs, h, op_stack->bp + op_stack->sz - 1);
        for (int _ = 0; _ < nArgs; ++_) {
          pop(op_stack);
        }
        push(op_stack, Bsexp);
        break;
      }
      case 3: {
        int val = pop(op_stack);
        int *addr = pop(op_stack);
        *addr = val;
        debug("STI");
        push(op_stack, val);
        break;
      }
      case 4: {
        debug("STA");
        int v = pop(op_stack);
        int i = pop(op_stack);
        int x = pop(op_stack);
        push(op_stack, Bsta(v, i, x));
        break;
      }
      case 5: {
        int addr = INT;
        debug("JMP\t0x%.8x", addr);
        ip = bf->code_ptr + addr;
        break;
      }
      case 6:
      case 7: {
        // `RET` is not used in stack machine code generation;
        // however, it behaves similarly to `END`.
        debug((l == 6) ? "END" : "RET");

        // Remember return value.
        int ret = pop(op_stack);

        // Remove local variables from the stack.
        for (int _ = 0; _ < current->nLocal; ++_)
          pop(op_stack);
        // Remove args from the stack.
        for (int _ = 0; _ < current->nArgs; ++_)
          pop(op_stack);

        // Remove closure from the stack if need.
        if (current->is_closure) {
          pop(op_stack);
        }

        // Push return value.
        push(op_stack, ret);

        ip = bf->code_ptr + current->ret_offset;
        current = current->prev;
        if (current == NULL) {
          goto stop;
        }
        break;
      }
      case 8: {
        debug("DROP");
        pop(op_stack);
        break;
      }
      case 9: {
        debug("DUP");
        int t = top(op_stack);
        push(op_stack, t);
        break;
      }
      case 10: {
        debug("SWAP");
        int a = pop(op_stack);
        int b = pop(op_stack);
        push(op_stack, a);
        push(op_stack, b);
        break;
      }
      case 11: {
        debug("ELEM");
        int index = pop(op_stack);
        int ar = pop(op_stack);
        push(op_stack, Belem(ar, index));
        break;
      }
      default:
        FAIL;
      }
      break;
    }

    case 2: {
      debug("LD");
      int *src = lda(current, op_stack, l, INT);
      push(op_stack, *src);
      break;
    }

    case 3: {
      debug("LDA");
      int addr = lda(current, op_stack, l, INT);
      push(op_stack, addr);
      push(op_stack, addr);
      break;
    }

    case 4: {
      debug("ST");
      int *dst = lda(current, op_stack, l, INT);
      debug("offset: %d\n", dst - op_stack->bp);
      *dst = top(op_stack);
      break;
    }

    case 5: {
      switch (l) {
      case 0: {
        int addr = INT;
        debug("CJMPz\t0x%.8x", addr);
        int cond = UNBOX(pop(op_stack));
        if (!cond) {
          ip = bf->code_ptr + addr;
        }
        break;
      }

      case 1: {
        int addr = INT;
        debug("CJMPnz\t0x%.8x", addr);
        int cond = UNBOX(pop(op_stack));
        if (cond) {
          ip = bf->code_ptr + addr;
        }
        break;
      }

      case 2:
      case 3: {
        int nArgs = INT;
        int nLocal = INT;
        debug(((l == 2) ? "BEGIN\t%d %d" : "CBEGIN\t%d %d"), nArgs, nLocal);

        // Reserve place for local args on the stack.
        current->nLocal = nLocal;
        for (int _ = 0; _ < nLocal; ++_)
          push(op_stack, 0);
        break;
      }

      case 4: {
        int addr = INT;
        int n = INT;
        debug("CLOSURE\t0x%.8x %d", addr, n);
        if (n > BUFF_SIZE) {
          failure("closure captured list doesn't fit into the buffer ");
        }
        for (int i = 0; i < n; ++i) {
          int typ = BYTE;
          int index = INT;
          buf[i] = *lda(current, op_stack, typ, index);
        }
        int closure = call_Bclosure(n, addr, buf + n - 1);
        push(op_stack, closure);
        break;
      }

      case 5: {
        int nArgs = INT;
        debug("CALLC\t%d", nArgs);

        // Pop arguments for reverse order.
        for (int i = 0; i < nArgs; ++i) {
          buf[i] = pop(op_stack);
        }

        // Take closure.
        int closure = top(op_stack);
        int addr = ((int *)closure)[0];
        int *captured = ((int *)closure) + 1;

        // Push args to the stack.
        for (int i = 0; i < nArgs; ++i) {
          push(op_stack, buf[i]);
        }

        int *ebp = &op_stack->bp[op_stack->sz];
        current =
            frame_new(ebp, nArgs, 0, ip - bf->code_ptr, 1, current);
        ip = bf->code_ptr + addr;
        break;
      }

      case 6: {
        int addr = INT;
        int nArgs = INT;
        debug("CALL\t0x%.8x %d", addr, nArgs);

        // Pop arguments for reverse order.
        for (int i = 0; i < nArgs; ++i) {
          buf[i] = pop(op_stack);
        }

        // Push args to the stack.
        for (int i = 0; i < nArgs; ++i) {
          push(op_stack, buf[i]);
        }

        int *ebp = &op_stack->bp[op_stack->sz];
        current = frame_new(ebp, nArgs, 0, ip - bf->code_ptr, 0, current);
        ip = bf->code_ptr + addr;
        break;
      }

      case 7: {
        char *name = STRING;
        int nArgs = INT;
        int h = hash(name);
        debug("TAG\t%s %d", name, nArgs);
        int arg = pop(op_stack);
        int res = Btag(arg, BOX(h), BOX(nArgs));
        push(op_stack, res);
        break;
      }

      case 8: {
        int n = INT;
        debug("ARRAY\t%d", n);
        int ar = pop(op_stack);
        push(op_stack, Barray_patt(ar, BOX(n)));
        break;
      }

      case 9: {
        debug("FAIL");
        int line = INT;
        int col = INT;
        int a = pop(op_stack);
        Bmatch_failure(a, filename, BOX(line), BOX(col));
        break;
      }

      case 10: {
        int line_num = INT;
        debug("LINE\t%d", line_num);
        break;
      }
      }
      break;
    }

    case 6: {
      debug("PATT %s", pats[l]);
      int t = pop(op_stack);
      int res = 0;
      switch (l) {
      case 0: {
        int e = pop(op_stack);
        res = Bstring_patt(t, e);
        break;
      }
      case 1:
        res = Bstring_tag_patt(t);
        break;
      case 2:
        res = Barray_tag_patt(t);
        break;
      case 3:
        res = Bsexp_tag_patt(t);
        break;
      case 4:
        res = Bboxed_patt(t);
        break;
      case 5:
        res = Bunboxed_patt(t);
        break;
      case 6:
        res = Bclosure_tag_patt(t);
        break;
      }
      push(op_stack, res);
      break;
    }

    case 7: {
      switch (l) {
      case 0:
        push(op_stack, Lread());
        break;

      case 1:
        debug("CALL Lwrite");
        int t = pop(op_stack);
        push(op_stack, Lwrite(t));
        break;

      case 2:
        debug("CALL Llength");
        int length = Llength(pop(op_stack));
        push(op_stack, length);
        break;

      case 3:
        debug("CALL Lstring");
        int str = Lstring(pop(op_stack));
        push(op_stack, str);
        break;

      case 4:
        debug("CALL Barray");
        int nArgs = INT;
        int Barray = call_Barray(nArgs, op_stack->bp + op_stack->sz - 1);
        for (int _ = 0; _ < nArgs; ++_) {
          pop(op_stack);
        }
        push(op_stack, Barray);
        break;

      default:
        FAIL;
        break;
      }

      break;
    }

    case 15:
      goto stop;

    default:
      FAIL;
    }

    debug("\n\n");
  }

stop:
  free(op_stack);
  free(buf);
}

int main(int argc, char *argv[]) {
  char *filename = argv[2];
  bytefile *f = read_file(filename);
  char *op = argv[1];
  if (!strcmp("-d", op)) {
    dump_file(stdout, f);
  } else if (!strcmp("-i", op)) {
    interpret(f, filename);
  } else {
    failure("unknown work mode ");
  }
  free(f);
  return 0;
}

int call_Bsexp(int n, int hash, int *args) {
  int boxed_hash = BOX(hash);
  // Put Sexp name hash on the stack.
  asm("pushl %0; " : : "r"(boxed_hash));

  // Put n args on the stack.
  asm("movl %0, %%ebx; "
      "movl %1, %%ecx; "
      "loop_Bsexp: "
      "cmpl $0, %%ebx; "
      "je done_Bsexp; "
      "pushl (%%ecx); "
      "subl $4, %%ecx; "
      "subl $1, %%ebx; "
      "jmp loop_Bsexp; "
      "done_Bsexp: "
      :
      : "r"(n), "r"(args)
      : "%ebx", "%ecx");

  int n_args = BOX(n + 1);
  int res = 0;

  // Put number of args on the stack,
  // call Bsexp.
  asm("pushl %0; "
      "call Bsexp; "
      "movl %%eax, %0;"
      : "=r"(res)
      : "r"(n_args));

  // Remove args from the stack.
  int args_to_clean = n + 2;
  asm("movl %0, %%ebx; "
      "loop_Bsexp_: "
      "cmpl $0, %%ebx; "
      "je done_Bsexp_; "
      "addl $4, %%esp; "
      "subl $1, %%ebx; "
      "jmp loop_Bsexp_; "
      "done_Bsexp_: "
      :
      : "r"(args_to_clean)
      : "%ebx");
  return res;
}

int call_Barray(int n, int *args) {
  // Put n args on the stack.
  asm("movl %0, %%ebx; "
      "movl %1, %%ecx; "
      "loop_Barray: "
      "cmpl $0, %%ebx; "
      "je done_Barray; "
      "pushl (%%ecx); "
      "subl $4, %%ecx; "
      "subl $1, %%ebx; "
      "jmp loop_Barray; "
      "done_Barray: "
      :
      : "r"(n), "r"(args)
      : "%ebx", "%ecx");

  int n_args = BOX(n);
  int res = 0;

  // Put number of args on the stack,
  // call Barray.
  asm("pushl %0; "
      "call Barray; "
      "movl %%eax, %0;"
      : "=r"(res)
      : "r"(n_args));

  // Remove args from the stack.
  int args_to_clean = n + 1;
  asm("movl %0, %%ebx; "
      "loop_Barray_: "
      "cmpl $0, %%ebx; "
      "je done_Barray_; "
      "addl $4, %%esp; "
      "subl $1, %%ebx; "
      "jmp loop_Barray_; "
      "done_Barray_: "
      :
      : "r"(args_to_clean)
      : "%ebx");
  return res;
}

int call_Bclosure(int n, int addr, int *args) {
  // Put n args on the stack.
  asm("movl %0, %%ebx; "
      "movl %1, %%ecx; "
      "loop_Bclosure: "
      "cmpl $0, %%ebx; "
      "je done_Bclosure; "
      "pushl (%%ecx); "
      "subl $4, %%ecx; "
      "subl $1, %%ebx; "
      "jmp loop_Bclosure; "
      "done_Bclosure: "
      :
      : "r"(n), "r"(args)
      : "%ebx", "%ecx");

  int res = 0;
  int n_args = BOX(n);

  // Put addr, number of args on the stack,
  // call Bclosure.
  asm("pushl %0" : : "r"(addr));
  asm("pushl %0; "
      "call Bclosure; "
      "movl %%eax, %0;"
      : "=r"(res)
      : "r"(n_args));

  // Clean the stack.
  int args_to_clean = n + 2;
  asm("movl %0, %%ebx; "
      "loop_Bclosure_: "
      "cmpl $0, %%ebx; "
      "je done_Bclosure_; "
      "addl $4, %%esp; "
      "subl $1, %%ebx; "
      "jmp loop_Bclosure_; "
      "done_Bclosure_: "
      :
      : "r"(args_to_clean)
      : "%ebx");
  return res;
}
