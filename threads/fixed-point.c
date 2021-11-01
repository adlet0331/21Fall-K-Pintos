// fixed-point 관련 처리

#include "threads/fixed-point.h"
#include <inttypes.h>

//Fixed Point
//  1       ..  17      ..  14
//  sign    ..  integer ..  decimal

int int_to_fp(int a){
    return a * F;
}
int fp_to_int(int a){
    return a / F;
}
int fp_round_int(int a){
    if (a & (1 << 13)){
        return (a + F / 2) / F;
    }
    else{
        return a / F;
    }
}

int fp_add_fp(int a, int b){
    return a + b;
}
int fp_int_add_fp(int a, int n){
    return a + n * F;
}
int fp_minus_fp(int a, int b){
    return a - b;
}
int fp_int_minus_fp(int a, int n){
    return a - n * F;
}
int int_fp_minus_fp(int n, int b){
    return n * F - b;
}
int fp_multiply_fp(int a, int b){
    return (((int64_t) a) * b) / F;
}
int fp_divide_fp(int a, int b){
    return (((int64_t) a) * F) / b;
}
int int_divide_int(int a, int b){
    int fp_a = int_to_fp(a);
    int fp_b = int_to_fp(b);
    int result = fp_divide_fp(fp_a, fp_b) * F;
    return fp_round_int(result);
}