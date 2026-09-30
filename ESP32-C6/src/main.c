#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_chip_info.h"
#include "esp_log.h"

static const char *TAG = "3t";

void app_main(void)
{
    esp_chip_info_t info;
    esp_chip_info(&info);
    ESP_LOGI(TAG, "Chip: ESP32-C6, cores=%d, revision=%d", info.cores, info.revision);

    int n = 0;
    while (1) {
        ESP_LOGI(TAG, "alive %d", n++);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}