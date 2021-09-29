#define F (1 << 14)
#define FP_MAX ((1 << 31) -1)
#define FP_MIN (-(1 << 31))

int int_to_fp(int);
int fp_to_int(int);
int fp_round_int(int);

int fp_add_fp(int, int);
int fp_int_add_fp(int, int);
int fp_minus_fp(int, int);
int fp_int_minus_fp(int, int);
int int_fp_minus_fp(int, int);
int fp_multiply_fp(int, int);
int fp_divide_fp(int, int);
int int_divide_int(int, int);