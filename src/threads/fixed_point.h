#define F (1 << 14)
#define FP_MAX (((1 << 32) - 1)/ F)

int convert_int_to_fp(int);
int convert_fp_to_int_round_zero(int);
int convert_fp_to_int_round_near(int);
int add_fp(int, int);
int subtract_fp(int, int);
int multiply_fp(int, int);
int multiply_fp_int(int, int);
int divide_fp(int, int);
int divide_fp_int(int, int);

