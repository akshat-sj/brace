/*
 * predict.h - Integer-only ML inference for soft-float targets
 * No FPU instructions, Q16.16 fixed-point arithmetic
 */

#ifndef PREDICT_H
#define PREDICT_H

#include <stdint.h>

#define FP_SCALE 65536

/* Predict function - implemented by generated model code */
int predict(const int64_t *features);

/* Get raw vote count (for custom thresholds) */
int64_t predict_votes(const int64_t *features);

#endif
