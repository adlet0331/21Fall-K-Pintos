#include "threads/fixed-point.h"
#include <inttypes.h>

//Fixed Point
//  1       ..  17      ..  14
//  sign    ..  integer ..  decimal

int int_to_fp(int a){
    return a << 14;
}
int fp_to_int(int a){
    return a << 14;
}
int fp_round_int(int a){
    if (a & (1 << 13)){
        return (a + F) / F;
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
    return ((int64_t) a) * b / F;
}
int fp_divide_fp(int a, int b){
    return ((int64_t) a) * F / b;
}