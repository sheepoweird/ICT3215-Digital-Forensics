#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "st7305.h"
#include <string.h>
#include <assert.h>
#include "nvs_flash.h"
#include "esp_log.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"

static const char *TAG = "badge_ble";
#define DEVICE_NAME "3T-Badge"          // <-- change to whatever name you want

// These two globals are what the screen will render in Goal 2.
static bool  s_connected = false;
static char  s_status[32] = "advertising";

static uint8_t own_addr_type;
static void ble_advertise(void);

static int gap_event(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_connected = true;
            strcpy(s_status, "connected");
            ESP_LOGI(TAG, "CONNECTED (handle=%d)", event->connect.conn_handle);
        } else {
            ESP_LOGI(TAG, "connect failed; status=%d", event->connect.status);
            ble_advertise();
        }
        return 0;
    case BLE_GAP_EVENT_DISCONNECT:
        s_connected = false;
        strcpy(s_status, "advertising");
        ESP_LOGI(TAG, "DISCONNECTED (reason=%d)", event->disconnect.reason);
        ble_advertise();
        return 0;
    case BLE_GAP_EVENT_ADV_COMPLETE:
        ble_advertise();
        return 0;
    default:
        return 0;
    }
}

static void ble_advertise(void) {
    struct ble_hs_adv_fields fields;
    memset(&fields, 0, sizeof(fields));
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)DEVICE_NAME;
    fields.name_len = strlen(DEVICE_NAME);
    fields.name_is_complete = 1;
    if (ble_gap_adv_set_fields(&fields) != 0) { ESP_LOGE(TAG, "adv_set_fields failed"); return; }

    struct ble_gap_adv_params adv_params;
    memset(&adv_params, 0, sizeof(adv_params));
    adv_params.conn_mode = BLE_GAP_CONN_MODE_UND;
    adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    int rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER,
                               &adv_params, gap_event, NULL);
    if (rc != 0) { ESP_LOGE(TAG, "adv_start rc=%d", rc); return; }
    ESP_LOGI(TAG, "advertising as '%s'", DEVICE_NAME);
}

static void on_sync(void) {
    assert(ble_hs_util_ensure_addr(0) == 0);
    if (ble_hs_id_infer_auto(0, &own_addr_type) != 0) { ESP_LOGE(TAG, "infer_auto failed"); return; }
    ble_advertise();
}

static void on_reset(int reason) { ESP_LOGE(TAG, "nimble reset; reason=%d", reason); }

static void draw_screen(void) {
    char line[48];
    st7305_clear();

    // header bar: black background, white text
    st7305_fill_rect(0, 0, LCD_WIDTH, 22, true);
    st7305_draw_text(8, 3, "Bluetooth is currently enabled", 1, false);

    snprintf(line, sizeof(line), "Name  : %s", DEVICE_NAME);
    st7305_draw_text(8, 34, line, 1, true);

    st7305_draw_text(8, 60, "Status:", 1, true);
    st7305_draw_text(8, 80, s_connected ? "CONNECTED" : "ADVERTISING", 2, true);

    st7305_flush();
}

static void host_task(void *param) {
    nimble_port_run();
    nimble_port_freertos_deinit();
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(st7305_init());   // screen first, so it is ready before BLE events

    ESP_ERROR_CHECK(nimble_port_init());

    ble_hs_cfg.sync_cb  = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    ble_svc_gap_init();
    ble_svc_gap_device_name_set(DEVICE_NAME);

    ESP_LOGI(TAG, "Bluetooth is currently enabled, name='%s'", DEVICE_NAME);
    
    // Redraw whenever the connection state changes
    bool last = !s_connected;
    while (1) {
        if (s_connected != last) {
            last = s_connected;
            draw_screen();
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}