// Copyright 2024 Wilhelm Schuster
// Copyright 2017 Balz Guenat
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "quantum.h"

#ifdef ACTUATION_DEPTH_ADJUSTMENT
#    include "ad5258.h"
#    include "actuation_point.h"
#endif

typedef union {
    uint32_t raw;
    struct {
        int8_t actuation_point_value;
    };
} keyboard_config_t;

void fc980c_matrix_init_kb(void);

void fc980c_eeconfig_update_kb(void);

void fc980c_eeconfig_init_kb(void);

void fc980c_keyboard_post_init_kb(void);
