#!/usr/bin/env python3
"""
Convert TL2cgen float model to integer-only C code for MIPS32.

Parses the TL2cgen main.c output and generates integer-only inference code.
"""

import re
import sys

# Fixed-point scale (Q16.16)
FP_SCALE = 65536

# Feature names for comments
FEATURE_NAMES = [
    "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Bwd Pkt Len Max", "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean", "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Fwd PSH Flags", "Pkt Len Max", "Pkt Len Var", "FIN Flag Cnt",
    "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt", "Down/Up Ratio",
    "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Seg Size Min", "Active Mean",
    "Active Std", "Idle Min"
]

def parse_tl2cgen(filename):
    """Parse TL2cgen main.c and extract tree structure."""
    with open(filename, 'r') as f:
        content = f.read()

    # Find the predict function body
    match = re.search(r'void predict\(union Entry\* data.*?\{(.+?)^\s*//\s*Average tree outputs',
                      content, re.DOTALL | re.MULTILINE)
    if not match:
        print("Could not find predict function")
        sys.exit(1)

    predict_body = match.group(1)
    return predict_body

def convert_condition(line):
    """Convert a TL2cgen condition to integer comparison."""
    # Pattern: data[X].fvalue <= (double)THRESHOLD
    match = re.search(r'data\[(\d+)\]\.fvalue\s*<=\s*\(double\)([\d.e+-]+)', line)
    if match:
        feature_idx = int(match.group(1))
        threshold = float(match.group(2))
        # Convert threshold to integer (truncate for <= comparison)
        int_threshold = int(threshold)
        return feature_idx, int_threshold
    return None, None

def convert_leaf(lines):
    """Extract malicious probability from leaf output."""
    # Pattern: result[1] += PROBABILITY
    for line in lines:
        match = re.search(r'result\[1\]\s*\+=\s*([\d.e+-]+)', line)
        if match:
            prob = float(match.group(1))
            # Convert to fixed-point
            return int(prob * FP_SCALE)
    return 0

def generate_integer_model(predict_body):
    """Generate integer-only C code from parsed tree."""

    lines = predict_body.split('\n')

    output_lines = []
    indent = 0

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Skip empty lines and variable declarations
        if not line or line.startswith('unsigned int'):
            i += 1
            continue

        # Handle if statements
        if line.startswith('if ('):
            feature_idx, threshold = convert_condition(line)
            if feature_idx is not None:
                feature_name = FEATURE_NAMES[feature_idx] if feature_idx < len(FEATURE_NAMES) else f"F{feature_idx}"
                output_lines.append(f"{'  ' * indent}if (f[{feature_idx}] <= {threshold}) {{ /* {feature_name} */")
                indent += 1
            else:
                # Keep original structure for debugging
                output_lines.append(f"{'  ' * indent}/* UNHANDLED: {line} */")
            i += 1
            continue

        # Handle else
        if line == '} else {':
            indent -= 1
            output_lines.append(f"{'  ' * indent}}} else {{")
            indent += 1
            i += 1
            continue

        # Handle closing brace
        if line == '}':
            indent -= 1
            output_lines.append(f"{'  ' * indent}}}")
            i += 1
            continue

        # Handle leaf nodes (result assignments)
        if 'result[0]' in line and 'result[1]' in line:
            # Single line with both results
            match = re.search(r'result\[1\]\s*\+=\s*([\d.e+-]+)', line)
            if match:
                prob = float(match.group(1))
                int_prob = int(prob * FP_SCALE)
                output_lines.append(f"{'  ' * indent}votes += {int_prob};")
            i += 1
            continue

        if 'result[0]' in line:
            # Look for result[1] on next line
            if i + 1 < len(lines) and 'result[1]' in lines[i+1]:
                match = re.search(r'result\[1\]\s*\+=\s*([\d.e+-]+)', lines[i+1])
                if match:
                    prob = float(match.group(1))
                    int_prob = int(prob * FP_SCALE)
                    output_lines.append(f"{'  ' * indent}votes += {int_prob};")
                i += 2
                continue

        i += 1

    return output_lines

def main():
    if len(sys.argv) < 2:
        input_file = "outputs/models/nids_rf_c/main.c"
    else:
        input_file = sys.argv[1]

    print(f"Parsing {input_file}...")
    predict_body = parse_tl2cgen(input_file)

    print("Generating integer model...")
    tree_code = generate_integer_model(predict_body)

    # Generate full C file
    c_code = '''/*
 * Integer-Only Random Forest Inference for MIPS32 (No FPU)
 * Auto-generated from TL2cgen output
 *
 * Features: 34 CICFlowMeter features
 * Model: Random Forest, 10 trees
 * Output: 0 = Benign, 1 = Malicious
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define N_FEATURES 34
#define N_TREES 10
#define FP_SCALE 65536  /* Q16.16 fixed-point */
#define THRESHOLD (N_TREES * FP_SCALE / 2)  /* 50% = 327680 */

/* Feature indices */
enum FeatureIdx {
    F_DST_PORT = 0,
    F_PROTOCOL = 1,
    F_FLOW_DURATION = 2,
    F_TOT_FWD_PKTS = 3,
    F_TOT_BWD_PKTS = 4,
    F_FWD_PKT_LEN_MAX = 5,
    F_FWD_PKT_LEN_MIN = 6,
    F_BWD_PKT_LEN_MAX = 7,
    F_BWD_PKT_LEN_MIN = 8,
    F_BWD_PKT_LEN_MEAN = 9,
    F_FLOW_BYTS_S = 10,
    F_FLOW_PKTS_S = 11,
    F_FLOW_IAT_MEAN = 12,
    F_FLOW_IAT_STD = 13,
    F_FLOW_IAT_MAX = 14,
    F_BWD_IAT_TOT = 15,
    F_BWD_IAT_MEAN = 16,
    F_BWD_IAT_STD = 17,
    F_BWD_IAT_MAX = 18,
    F_FWD_PSH_FLAGS = 19,
    F_PKT_LEN_MAX = 20,
    F_PKT_LEN_VAR = 21,
    F_FIN_FLAG_CNT = 22,
    F_RST_FLAG_CNT = 23,
    F_PSH_FLAG_CNT = 24,
    F_ACK_FLAG_CNT = 25,
    F_URG_FLAG_CNT = 26,
    F_DOWN_UP_RATIO = 27,
    F_INIT_FWD_WIN_BYTS = 28,
    F_INIT_BWD_WIN_BYTS = 29,
    F_FWD_SEG_SIZE_MIN = 30,
    F_ACTIVE_MEAN = 31,
    F_ACTIVE_STD = 32,
    F_IDLE_MIN = 33
};

/*
 * Main prediction function
 * Returns: 0 = Benign, 1 = Malicious
 *
 * All trees are combined into a single function for efficiency.
 * votes accumulates the malicious probability across all trees.
 */
int predict(const int64_t *f) {
    int64_t votes = 0;

'''

    c_code += '\n'.join(f'    {line}' for line in tree_code)

    c_code += '''

    /* Majority voting: if more than half the trees vote malicious */
    return (votes > THRESHOLD) ? 1 : 0;
}

/*
 * Parse a single CSV line into features
 */
int parse_csv_line(const char *line, int64_t *features) {
    char *copy = strdup(line);
    char *token = strtok(copy, ",");
    int idx = 0;

    while (token && idx < N_FEATURES) {
        double val = atof(token);
        /* Truncate to integer for comparison */
        features[idx++] = (int64_t)val;
        token = strtok(NULL, ",");
    }

    free(copy);
    return idx;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <flow_csv> [threshold]\\n", argv[0]);
        printf("  Classifies network flows as Benign (0) or Malicious (1)\\n");
        printf("  threshold: detection threshold 0.0-1.0 (default: 0.5)\\n");
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("Error opening file");
        return 1;
    }

    /* Parse optional threshold */
    double thresh_pct = 0.5;
    if (argc >= 3) {
        thresh_pct = atof(argv[2]);
        if (thresh_pct < 0.0 || thresh_pct > 1.0) {
            fprintf(stderr, "Threshold must be between 0.0 and 1.0\\n");
            return 1;
        }
    }
    int64_t custom_threshold = (int64_t)(thresh_pct * N_TREES * FP_SCALE);

    char line[4096];
    int64_t features[N_FEATURES];
    int line_num = 0;
    int malicious_count = 0;
    int total_count = 0;

    /* Skip header */
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return 1;
    }

    /* Process each flow */
    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Skip empty lines */
        if (strlen(line) < 10) continue;

        /* Parse features */
        memset(features, 0, sizeof(features));
        if (parse_csv_line(line, features) < N_FEATURES) {
            fprintf(stderr, "Warning: Line %d has insufficient features\\n", line_num);
            continue;
        }

        /* Get raw vote count for custom threshold */
        int64_t votes = 0;
        /* Re-run prediction logic to get votes */
        {
            const int64_t *f = features;
'''

    # Add vote calculation (same as predict but captures votes)
    c_code += '\n'.join(f'            {line}' for line in tree_code)

    c_code += '''
        }

        int result = (votes > custom_threshold) ? 1 : 0;
        total_count++;

        if (result == 1) {
            malicious_count++;
            printf("[ALERT] Line %d: MALICIOUS (votes=%ld/%ld)\\n",
                   line_num, (long)votes, (long)(N_TREES * FP_SCALE));
        }
    }

    fclose(fp);

    /* Summary */
    printf("\\n=== Classification Summary ===\\n");
    printf("Threshold: %.0f%%\\n", thresh_pct * 100);
    printf("Total flows: %d\\n", total_count);
    printf("Malicious:   %d (%.2f%%)\\n", malicious_count,
           total_count > 0 ? 100.0 * malicious_count / total_count : 0.0);
    printf("Benign:      %d (%.2f%%)\\n", total_count - malicious_count,
           total_count > 0 ? 100.0 * (total_count - malicious_count) / total_count : 0.0);

    return malicious_count > 0 ? 1 : 0;
}
'''

    output_file = "mips-ml/model_integer.c"
    with open(output_file, 'w') as f:
        f.write(c_code)

    print(f"Generated {output_file}")
    print(f"Tree code lines: {len(tree_code)}")

if __name__ == "__main__":
    main()
