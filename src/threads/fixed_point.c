#include "threads/fixed_point.h"
#include <stdint.h>
int convert_int_to_fp(int n)
{
    return (n*F);
}

int convert_fp_to_int_round_zero(int x)
{
    return x / F;
}

int convert_fp_to_int_round_near(int x)
{
    if(x >= 0) return (x + F / 2) / F;
    else return (x - F / 2) / F;
}

int add_fp(int x, int y)
{
    return x + y;
}
/*return x - y*/
int subtract_fp(int x, int y)
{
    return x - y;
}

int multiply_fp(int x, int y)
{
    return ((int64_t)x)*y/F;
}

int multiply_fp_int(int x, int n)
{
    return x * n;
}

int divide_fp(int x, int y)
{
    return ((int64_t)x)*F/y;
}

int divide_fp_int(int x, int n)
{
    return x / n;
}

