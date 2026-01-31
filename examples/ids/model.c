/*
 * Integer-only Random Forest for Network Intrusion Detection
 * Target: MIPS32/ARM without FPU (soft-float ABI)
 * Input: 34 CICFlowMeter features, Output: 0=Benign, 1=Malicious
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define N_FEATURES 34
#define N_TREES 10
#define FP_SCALE 65536

static int64_t predict_votes(const int64_t *f) {
    int64_t v = 0;

    /* Tree 0 */
    if (f[20] <= 0) {
        if (f[33] <= 55728076) {
            if (f[30] <= 30) {
                if (f[14] <= 400) { v += (f[12] <= 320) ? 390 : 18370; }
                else { v += (f[28] <= 32434) ? 0 : 65365; }
            } else {
                if (f[25] <= 0) { v += (f[18] <= 0) ? 65151 : 0; }
                else { v += (f[16] <= 61) ? 65458 : 0; }
            }
        } else {
            if (f[28] <= 110) { v += 0; }
            else { v += (f[18] <= 29172204) ? ((f[33] <= 70118404) ? 61322 : 467) : 0; }
        }
    } else {
        if (f[30] <= 30) {
            if (f[15] <= 1045) {
                if (f[17] <= 345) { v += (f[4] <= 0) ? 2589 : 17; }
                else { v += (f[13] <= 217) ? 38166 : 0; }
            } else {
                if (f[5] <= 365) { v += (f[14] <= 26194) ? 61700 : 1241; }
                else { v += 0; }
            }
        } else {
            if (f[3] <= 21) {
                if (f[15] <= 3027064) { v += (f[21] <= 26737) ? 54254 : 64779; }
                else { v += (f[13] <= 1150292) ? 38550 : 65505; }
            } else { v += (f[5] <= 808) ? 65536 : 0; }
        }
    }

    /* Tree 1 */
    if (f[0] <= 80) {
        if (f[12] <= 40) {
            if (f[4] <= 0) {
                if (f[11] <= 62561) { v += 8192; }
                else { v += (f[14] <= 24) ? 64212 : 51200; }
            } else {
                if (f[11] <= 114379) { v += (f[30] <= 28) ? 0 : 65521; }
                else { v += (f[0] <= 22) ? 65536 : 64180; }
            }
        } else {
            if (f[8] <= 15) {
                if (f[12] <= 178) { v += (f[9] <= 198) ? 508 : 65536; }
                else { v += (f[11] <= 1) ? 29899 : 63706; }
            } else { v += 0; }
        }
    } else { v += 0; }

    /* Tree 2 */
    if (f[10] <= 0) {
        if (f[16] <= 0) {
            if (f[29] <= 233) {
                if (f[0] <= 80) { v += (f[14] <= 52105076) ? 62674 : 1441; }
                else { v += 0; }
            } else {
                if (f[11] <= 267857) { v += 0; }
                else { v += (f[30] <= 26) ? 0 : 65536; }
            }
        } else {
            if (f[11] <= 0) { v += (f[31] <= 13) ? 65536 : 62415; }
            else { v += 0; }
        }
    } else {
        if (f[13] <= 1394) {
            if (f[7] <= 509) {
                if (f[6] <= 4) { v += (f[30] <= 26) ? 0 : 35498; }
                else { v += (f[12] <= 14) ? 52769 : 7; }
            } else {
                if (f[14] <= 3547) { v += (f[28] <= 32895) ? 62557 : 65536; }
                else { v += 23405; }
            }
        } else {
            if (f[7] <= 661) {
                if (f[18] <= 71899660) { v += (f[21] <= 28) ? 13733 : 462; }
                else { v += (f[3] <= 4) ? 7710 : 65536; }
            } else {
                if (f[20] <= 976) { v += (f[33] <= 7015307) ? 64790 : 123; }
                else { v += 0; }
            }
        }
    }

    /* Tree 3 */
    if (f[12] <= 20) {
        if (f[21] <= 48) {
            if (f[27] <= 0) {
                if (f[30] <= 26) { v += (f[5] <= 6) ? 2073 : 0; }
                else { v += 65536; }
            } else {
                if (f[0] <= 80) { v += (f[26] <= 0) ? 65501 : 65536; }
                else { v += 0; }
            }
        } else { v += 0; }
    } else {
        if (f[4] <= 0) {
            if (f[28] <= 26722) {
                if (f[30] <= 30) { v += (f[1] <= 11) ? 44 : 7538; }
                else { v += (f[3] <= 2) ? 62781 : 0; }
            } else {
                if (f[11] <= 7421) { v += (f[12] <= 1729455) ? 65351 : 0; }
                else { v += (f[0] <= 109) ? 23831 : 0; }
            }
        } else {
            if (f[9] <= 233) {
                if (f[17] <= 19920) { v += (f[18] <= 99865844) ? 804 : 65152; }
                else { v += (f[11] <= 91) ? 8180 : 65252; }
            } else {
                if (f[4] <= 4) { v += (f[21] <= 43573) ? 0 : 65180; }
                else { v += 0; }
            }
        }
    }

    /* Tree 4 */
    if (f[28] <= 26865) {
        if (f[28] <= 241) {
            if (f[30] <= 30) {
                if (f[20] <= 32) { v += (f[6] <= 31) ? 265 : 22919; }
                else { v += 0; }
            } else {
                if (f[26] <= 0) { v += (f[14] <= 3225) ? 64220 : 65536; }
                else { v += (f[12] <= 220) ? 65533 : 9039; }
            }
        } else { v += 0; }
    } else {
        if (f[29] <= 240) {
            if (f[4] <= 0) {
                if (f[12] <= 264) { v += (f[28] <= 32739) ? 40499 : 0; }
                else { v += (f[28] <= 32985) ? 65461 : 0; }
            } else {
                if (f[24] <= 0) { v += 0; }
                else { v += (f[0] <= 80) ? 65521 : 0; }
            }
        } else {
            if (f[16] <= 24459534) {
                if (f[0] <= 109) { v += (f[18] <= 11088) ? 59578 : 0; }
                else { v += 0; }
            } else { v += 65536; }
        }
    }

    /* Tree 5 */
    if (f[0] <= 80) {
        if (f[21] <= 31) {
            if (f[0] <= 10) { v += 0; }
            else {
                if (f[14] <= 2782244) { v += (f[3] <= 1) ? 65311 : 60611; }
                else { v += (f[30] <= 30) ? 0 : 64216; }
            }
        } else {
            if (f[17] <= 302) {
                if (f[5] <= 195) { v += (f[8] <= 19) ? 135 : 0; }
                else { v += (f[13] <= 56) ? 1017 : 63142; }
            } else {
                if (f[7] <= 931) { v += (f[9] <= 5) ? 65443 : 15934; }
                else { v += (f[20] <= 976) ? 65359 : 0; }
            }
        }
    } else { v += 0; }

    /* Tree 6 */
    if (f[13] <= 0) {
        if (f[5] <= 0) {
            if (f[11] <= 0) {
                if (f[14] <= 57249964) { v += (f[12] <= 52474540) ? 19275 : 355; }
                else { v += (f[33] <= 73244636) ? 41208 : 135; }
            } else {
                if (f[28] <= 26722) { v += (f[11] <= 190909) ? 13378 : 63330; }
                else { v += (f[14] <= 78735) ? 64844 : 327; }
            }
        } else {
            if (f[10] <= 1579411) { v += (f[30] <= 26) ? 0 : 65536; }
            else {
                if (f[2] <= 1) { v += (f[28] <= 224) ? 8738 : 0; }
                else { v += (f[30] <= 26) ? 0 : 64493; }
            }
        }
    } else {
        if (f[7] <= 661) {
            if (f[30] <= 30) {
                if (f[14] <= 540035) { v += 0; }
                else { v += (f[12] <= 12152) ? 65095 : 0; }
            } else {
                if (f[12] <= 413050) { v += (f[0] <= 262) ? 62548 : 0; }
                else { v += (f[21] <= 9) ? 51011 : 65376; }
            }
        } else {
            if (f[13] <= 36631) {
                if (f[28] <= 20741) { v += 0; }
                else { v += (f[3] <= 26) ? 65534 : 61680; }
            } else {
                if (f[11] <= 1) { v += (f[14] <= 7006376) ? 62720 : 460; }
                else { v += (f[28] <= 25443) ? 0 : 27043; }
            }
        }
    }

    /* Tree 7 */
    if (f[14] <= 20) {
        if (f[21] <= 106) {
            if (f[3] <= 1) {
                if (f[30] <= 30) { v += 0; }
                else { v += (f[0] <= 107) ? 65535 : 0; }
            } else {
                if (f[4] <= 0) { v += (f[28] <= 32710) ? 1382 : 35368; }
                else { v += 65536; }
            }
        } else { v += (f[20] <= 233) ? 0 : 4096; }
    } else {
        if (f[11] <= 1927) {
            if (f[30] <= 30) {
                if (f[4] <= 0) { v += (f[20] <= 0) ? 59443 : 5303; }
                else { v += (f[11] <= 214) ? 762 : 20591; }
            } else {
                if (f[30] <= 34) { v += (f[28] <= 27041) ? 64947 : 0; }
                else { v += (f[31] <= 1448900) ? 47473 : 0; }
            }
        } else {
            if (f[27] <= 0) {
                if (f[0] <= 109) { v += (f[12] <= 367) ? 1769 : 62858; }
                else { v += 0; }
            } else {
                if (f[21] <= 37355) { v += (f[10] <= 32770) ? 14228 : 2; }
                else { v += (f[7] <= 484) ? 8548 : 65508; }
            }
        }
    }

    /* Tree 8 */
    if (f[7] <= 0) {
        if (f[14] <= 48632) {
            if (f[10] <= 11) {
                if (f[28] <= 26125) { v += (f[25] <= 0) ? 3676 : 38686; }
                else { v += (f[29] <= 125) ? 65124 : 0; }
            } else {
                if (f[0] <= 261) { v += (f[12] <= 18) ? 65536 : 36700; }
                else { v += 0; }
            }
        } else {
            if (f[16] <= 52246636) {
                if (f[2] <= 1577294) { v += (f[0] <= 97) ? 24015 : 0; }
                else { v += (f[2] <= 52331362) ? 47011 : 6714; }
            } else { v += (f[30] <= 26) ? 0 : 65536; }
        }
    } else {
        if (f[13] <= 1371) {
            if (f[15] <= 1081) {
                if (f[26] <= 0) { v += (f[7] <= 742) ? 0 : 65536; }
                else { v += (f[10] <= 2048973) ? 59294 : 65536; }
            } else {
                if (f[29] <= 2033) { v += (f[9] <= 198) ? 0 : 65502; }
                else { v += 0; }
            }
        } else {
            if (f[29] <= 230) {
                if (f[9] <= 121) { v += 0; }
                else { v += (f[28] <= 20741) ? 85 : 65522; }
            } else {
                if (f[4] <= 19) { v += 0; }
                else { v += (f[15] <= 416128) ? 3733 : 0; }
            }
        }
    }

    /* Tree 9 */
    if (f[5] <= 641) {
        if (f[31] <= 10535) {
            if (f[30] <= 14) {
                if (f[20] <= 32) { v += (f[30] <= 4) ? 0 : 13749; }
                else { v += 0; }
            } else {
                if (f[16] <= 23529) { v += (f[25] <= 0) ? 59447 : 50810; }
                else { v += (f[0] <= 109) ? 41335 : 0; }
            }
        } else {
            if (f[27] <= 0) {
                if (f[31] <= 5499986) { v += (f[18] <= 74312048) ? 1548 : 62914; }
                else { v += (f[15] <= 4461284) ? 2915 : 65310; }
            } else {
                if (f[14] <= 6832527) { v += (f[17] <= 3173594) ? 0 : 26214; }
                else { v += 0; }
            }
        }
    } else {
        if (f[18] <= 5000100) {
            if (f[10] <= 33) { v += 56173; }
            else {
                if (f[21] <= 133653) { v += (f[0] <= 261) ? 13797 : 0; }
                else { v += (f[28] <= 17537) ? 0 : 37449; }
            }
        } else {
            if (f[30] <= 26) { v += 0; }
            else { v += (f[5] <= 743) ? 65536 : 60293; }
        }
    }

    return v;
}

static int64_t parse_int(const char *s) {
    int64_t r = 0;
    int neg = 0;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') r = r * 10 + (*s++ - '0');
    return neg ? -r : r;
}

static int parse_csv(const char *line, int64_t *f) {
    char *copy = strdup(line);
    char *tok = strtok(copy, ",");
    int i = 0;
    while (tok && i < N_FEATURES) { f[i++] = parse_int(tok); tok = strtok(NULL, ","); }
    free(copy);
    return i;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <csv> [threshold%%]\n", argv[0]);
        printf("Classifies flows: 0=Benign, 1=Malicious\n");
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) { perror(argv[1]); return 1; }

    int thresh_pct = argc >= 3 ? (int)parse_int(argv[2]) : 50;
    if (thresh_pct < 0 || thresh_pct > 100) thresh_pct = 50;
    int64_t threshold = ((int64_t)thresh_pct * N_TREES * FP_SCALE) / 100;

    char line[4096];
    int64_t features[N_FEATURES];
    int total = 0, malicious = 0;

    fgets(line, sizeof(line), fp); /* skip header */

    while (fgets(line, sizeof(line), fp)) {
        if (strlen(line) < 10) continue;
        memset(features, 0, sizeof(features));
        if (parse_csv(line, features) < N_FEATURES) continue;

        int64_t votes = predict_votes(features);
        total++;
        if (votes > threshold) {
            malicious++;
            printf("[ALERT] Flow %d: MALICIOUS (score=%ld/%ld)\n",
                   total, (long)votes, (long)(N_TREES * FP_SCALE));
        }
    }

    fclose(fp);

    printf("\n=== Results ===\n");
    printf("Threshold: %d%%\n", thresh_pct);
    printf("Total: %d\n", total);
    printf("Malicious: %d (%d%%)\n", malicious, total ? (100*malicious)/total : 0);
    printf("Benign: %d (%d%%)\n", total-malicious, total ? (100*(total-malicious))/total : 0);

    return malicious > 0 ? 1 : 0;
}
