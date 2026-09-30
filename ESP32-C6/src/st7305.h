#pragma once

#include <stdbool.h>
#include "esp_err.h"

/*
 * ST7305 reflective mono LCD on the badge (168x384 panel).
 *
 * Pins and init sequence were recovered from the stock "glint_badge"
 * firmware in badge_full_backup.bin:
 *   SPI2_HOST, MOSI=GPIO14, SCLK=GPIO15, CS=GPIO8, DC=GPIO18, RST=GPIO9, 20 MHz
 *
 * The stock UI runs landscape (384 wide x 168 tall); these coordinates follow
 * the same orientation.
 */
#define LCD_WIDTH  384
#define LCD_HEIGHT 168

esp_err_t st7305_init(void);

/* Drawing goes to a RAM framebuffer; call st7305_flush() to push it. */
void st7305_clear(void);
void st7305_set_pixel(int x, int y, bool on);
void st7305_fill_rect(int x, int y, int w, int h, bool on);
/* Draws ASCII text with the 8x16 font, scaled by `scale`. Returns the x after the text. */
int st7305_draw_text(int x, int y, const char *s, int scale, bool on);
esp_err_t st7305_flush(void);
