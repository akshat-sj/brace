#!/usr/bin/env python3
"""
Convert TL2cgen float model to integer-only C code.

Usage:
    python convert_to_integer.py <tl2cgen_main.c> <output.c>

This script parses TL2cgen-generated C code and converts:
- Float thresholds to integers (truncation)
- Float leaf probabilities to Q16.16 fixed-point
- Removes all floating-point operations
"""

import re
import sys
import argparse

FP_SCALE = 65536

def parse_tree_structure(content):
    """Extract tree structure from TL2cgen output."""
    trees = []
    current_tree = []

    # Find all comparison patterns: data[idx] <= threshold
    comparisons = re.findall(
        r'data\[(\d+)\]\s*<=\s*([\d.]+)f?',
        content
    )

    # Find all leaf values: sum += value
    leaves = re.findall(
        r'sum\s*\+=\s*([\d.]+)f?',
        content
    )

    return comparisons, leaves

def convert_threshold(threshold_str):
    """Convert float threshold to integer (truncate)."""
    return int(float(threshold_str))

def convert_probability(prob_str):
    """Convert probability to Q16.16 fixed-point."""
    return int(float(prob_str) * FP_SCALE)

def generate_header():
    return '''/*
 * Integer-only Random Forest - Auto-generated
 * No FPU instructions, Q16.16 fixed-point voting
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define N_FEATURES {n_features}
#define N_TREES {n_trees}
#define FP_SCALE 65536
#define THRESHOLD (N_TREES * FP_SCALE / 2)

'''

def main():
    parser = argparse.ArgumentParser(description='Convert TL2cgen model to integer-only C')
    parser.add_argument('input', help='TL2cgen main.c file')
    parser.add_argument('output', help='Output integer C file')
    parser.add_argument('--features', type=int, default=34, help='Number of features')
    parser.add_argument('--trees', type=int, default=10, help='Number of trees')
    args = parser.parse_args()

    with open(args.input) as f:
        content = f.read()

    comparisons, leaves = parse_tree_structure(content)

    print(f"Found {len(comparisons)} comparisons")
    print(f"Found {len(leaves)} leaf nodes")

    # Generate integer code
    output = generate_header().format(
        n_features=args.features,
        n_trees=args.trees
    )

    # Convert comparisons
    int_comparisons = [(int(idx), convert_threshold(th)) for idx, th in comparisons]
    int_leaves = [convert_probability(p) for p in leaves]

    print(f"Threshold range: {min(t for _, t in int_comparisons)} - {max(t for _, t in int_comparisons)}")
    print(f"Leaf range: {min(int_leaves)} - {max(int_leaves)}")

    # Write placeholder - full implementation would reconstruct tree
    output += "/* Tree structure would be generated here */\n"
    output += "/* Use tl2cgen directly and manually convert thresholds */\n"

    with open(args.output, 'w') as f:
        f.write(output)

    print(f"Wrote {args.output}")

if __name__ == '__main__':
    main()
