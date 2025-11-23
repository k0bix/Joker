#pragma once

#include <Arduino.h>
#include "InterruptButton.h"
#include "zero_log.h"

#define ESP32_DELAY(x) delay(x); yield();

#define LED 10

#define UP_BUTTON_PIN 41
#define DOWN_BUTTON_PIN 39
#define LEFT_BUTTON_PIN 38
#define RIGHT_BUTTON_PIN 40
#define A_BUTTON_PIN 7
#define B_BUTTON_PIN 6

InterruptButton btn_up(UP_BUTTON_PIN, LOW);
InterruptButton btn_down(DOWN_BUTTON_PIN, LOW);
InterruptButton btn_left(LEFT_BUTTON_PIN, LOW);
InterruptButton btn_right(RIGHT_BUTTON_PIN, LOW);
InterruptButton btn_a(A_BUTTON_PIN, LOW);
InterruptButton btn_b(B_BUTTON_PIN, LOW);